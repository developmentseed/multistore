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
use std::net::IpAddr;
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
    /// Headers to merge onto the client-facing response after forwarding.
    pub response_headers: HeaderMap,
    /// Unique request identifier for tracing and metering correlation.
    pub request_id: String,
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
    pub(crate) operation: crate::types::S3Operation,
    pub(crate) bucket_config: crate::types::BucketConfig,
    pub(crate) original_headers: HeaderMap,
    pub(crate) request_id: String,
    /// Headers to merge onto the client-facing response after body processing.
    pub(crate) response_headers: HeaderMap,
}

impl HandlerAction {
    /// Mutable access to headers that will be merged onto the client response.
    ///
    /// For `Response`, this returns the response headers directly.
    /// For `Forward` and `NeedsBody`, returns supplemental headers that the
    /// gateway merges after forwarding/body processing.
    pub fn response_headers_mut(&mut self) -> &mut HeaderMap {
        match self {
            Self::Response(r) => &mut r.headers,
            Self::Forward(f) => &mut f.response_headers,
            Self::NeedsBody(p) => &mut p.response_headers,
        }
    }
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
    /// The IP address of the client that originated this request.
    ///
    /// Populated by runtimes that can extract client addresses (e.g. from
    /// `ConnectInfo` in axum, or request headers in Lambda/Workers).
    /// `None` when the source IP is unavailable or not yet extracted.
    pub source_ip: Option<IpAddr>,
    /// Path parameters extracted by the router during dispatch.
    ///
    /// Populated by the router when a route pattern matches. Empty when the
    /// request is constructed via [`RequestInfo::new`].
    pub params: Params,
}

impl<'a> RequestInfo<'a> {
    /// Create a new `RequestInfo` from the parsed HTTP request components.
    pub fn new(
        method: &'a Method,
        path: &'a str,
        query: Option<&'a str>,
        headers: &'a HeaderMap,
        source_ip: Option<IpAddr>,
    ) -> Self {
        Self {
            method,
            path,
            query,
            headers,
            source_ip,
            params: Params::default(),
        }
    }
}

/// A pluggable handler that can intercept requests before proxy dispatch.
///
/// Implementations inspect the [`RequestInfo`] and return:
/// - `Some(result)` to handle the request (stops further handler checks)
/// - `None` to pass the request to the next handler or the proxy
///
/// ```rust,ignore
/// struct HealthCheck;
///
/// impl RouteHandler for HealthCheck {
///     fn handle<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
///         Box::pin(async move {
///             Some(ProxyResult::json(200, r#"{"ok":true}"#))
///         })
///     }
/// }
///
/// router.route("/health", HealthCheck);
/// ```
pub trait RouteHandler: MaybeSend + MaybeSync {
    /// Handle an incoming request.
    ///
    /// Return `Some(result)` to short-circuit, or `None` to fall through
    /// to the next handler or the proxy dispatch pipeline.
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a>;
}
