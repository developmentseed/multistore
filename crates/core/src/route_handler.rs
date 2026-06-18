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
    /// Unique request identifier for tracing and metering correlation.
    pub request_id: String,
}

/// The result of handling a proxy request.
pub struct ProxyResult {
    /// HTTP status code for the response.
    pub status: u16,
    /// Response headers to send to the client.
    pub headers: HeaderMap,
    /// Response body (XML, JSON, or empty).
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
}

/// Response headers that must NOT be forwarded to clients.
///
/// Uses a denylist approach: all headers pass through except those that are
/// genuinely dangerous to forward from a reverse proxy. This allows cloud
/// provider metadata (x-amz-meta-*, x-ms-meta-*, x-goog-meta-*) and useful
/// operational headers to flow through without explicit allowlisting.
pub const RESPONSE_HEADER_DENYLIST: &[&str] = &[
    // Hop-by-hop (RFC 7230 §6.1)
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    // Auth/cookies
    "proxy-authenticate",
    "proxy-authorization",
    "www-authenticate",
    "set-cookie",
    // Proxy routing
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "via",
    // Encryption key material (lets attackers validate guessed keys)
    "x-amz-server-side-encryption-customer-key-md5",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-ms-encryption-key-sha256",
    "x-goog-encryption-key-sha256",
];

/// Filter a `HeaderMap` by removing headers in the [`RESPONSE_HEADER_DENYLIST`].
///
/// Blocks hop-by-hop, auth/cookie, proxy routing, and encryption key material
/// headers. Everything else (content metadata, cloud provider headers, user
/// metadata) passes through.
pub fn filter_response_headers(source: &http::HeaderMap) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in source.iter() {
        if !RESPONSE_HEADER_DENYLIST.contains(&name.as_str()) {
            out.insert(name.clone(), value.clone());
        }
    }
    out
}

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
    /// The HTTP method (GET, PUT, HEAD, etc.).
    pub method: &'a Method,
    /// The URL path (e.g. "/bucket/key").
    pub path: &'a str,
    /// The raw query string, if present.
    pub query: Option<&'a str>,
    /// The HTTP request headers.
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
    /// The original path as seen by the client, used for SigV4 signature
    /// verification when the proxy rewrites paths before dispatch.
    ///
    /// When `None`, `path` is used for both operation parsing and signature
    /// verification.
    pub signing_path: Option<&'a str>,
    /// The original query string as seen by the client, used for SigV4
    /// signature verification when the proxy rewrites query parameters.
    ///
    /// When `None`, `query` is used for both operation parsing and signature
    /// verification.
    pub signing_query: Option<&'a str>,
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
            signing_path: None,
            signing_query: None,
        }
    }

    /// Set the original client-facing path for SigV4 signature verification.
    ///
    /// Use this when the proxy rewrites paths (e.g. path-mapping) so that
    /// signature verification uses the path the client actually signed.
    pub fn with_signing_path(mut self, signing_path: &'a str) -> Self {
        self.signing_path = Some(signing_path);
        self
    }

    /// Set the original client-facing query string for SigV4 signature verification.
    ///
    /// Use this when the proxy rewrites query parameters (e.g. path-mapping
    /// strips prefix segments from the `prefix` parameter) so that signature
    /// verification uses the query string the client actually signed.
    pub fn with_signing_query(mut self, signing_query: Option<&'a str>) -> Self {
        self.signing_query = signing_query;
        self
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_hop_by_hop_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("connection", "keep-alive".parse().unwrap());
        headers.insert("content-type", "text/plain".parse().unwrap());

        let filtered = filter_response_headers(&headers);
        assert!(filtered.get("transfer-encoding").is_none());
        assert!(filtered.get("connection").is_none());
        assert!(filtered.get("content-type").is_some());
    }

    #[test]
    fn test_blocks_auth_and_cookie_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("www-authenticate", "Basic".parse().unwrap());
        headers.insert("set-cookie", "session=abc".parse().unwrap());
        headers.insert("etag", "\"abc\"".parse().unwrap());

        let filtered = filter_response_headers(&headers);
        assert!(filtered.get("www-authenticate").is_none());
        assert!(filtered.get("set-cookie").is_none());
        assert!(filtered.get("etag").is_some());
    }

    #[test]
    fn test_blocks_encryption_key_material() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-server-side-encryption-aws-kms-key-id",
            "arn:aws:kms:us-east-1:123456:key/abc".parse().unwrap(),
        );
        headers.insert(
            "x-amz-server-side-encryption-customer-key-md5",
            "abc123".parse().unwrap(),
        );
        headers.insert("x-amz-server-side-encryption", "aws:kms".parse().unwrap());

        let filtered = filter_response_headers(&headers);
        assert!(filtered
            .get("x-amz-server-side-encryption-aws-kms-key-id")
            .is_none());
        assert!(filtered
            .get("x-amz-server-side-encryption-customer-key-md5")
            .is_none());
        // Encryption method (not key material) should pass through
        assert!(filtered.get("x-amz-server-side-encryption").is_some());
    }

    #[test]
    fn test_passes_cloud_metadata_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-meta-author", "alice".parse().unwrap());
        headers.insert("x-ms-meta-version", "2".parse().unwrap());
        headers.insert("x-goog-meta-project", "test".parse().unwrap());
        headers.insert("x-amz-storage-class", "STANDARD".parse().unwrap());
        headers.insert("x-amz-version-id", "v1".parse().unwrap());

        let filtered = filter_response_headers(&headers);
        assert_eq!(filtered.len(), 5);
    }

    #[test]
    fn test_passes_standard_content_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("content-length", "1234".parse().unwrap());
        headers.insert("content-range", "bytes 0-499/1000".parse().unwrap());
        headers.insert("etag", "\"abc\"".parse().unwrap());
        headers.insert(
            "last-modified",
            "Mon, 01 Jan 2024 00:00:00 GMT".parse().unwrap(),
        );
        headers.insert("accept-ranges", "bytes".parse().unwrap());
        headers.insert("cache-control", "max-age=3600".parse().unwrap());
        headers.insert("location", "/new".parse().unwrap());

        let filtered = filter_response_headers(&headers);
        assert_eq!(filtered.len(), 8);
    }

    #[test]
    fn test_blocks_proxy_routing_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        headers.insert("via", "1.1 proxy".parse().unwrap());
        headers.insert("forwarded", "for=1.2.3.4".parse().unwrap());

        let filtered = filter_response_headers(&headers);
        assert!(filtered.is_empty());
    }
}
