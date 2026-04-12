//! Request parsing helpers for Cloudflare Workers.
//!
//! Provides [`RequestParts`] to extract owned HTTP metadata from a
//! `web_sys::Request`, and convert it into the borrowed
//! [`RequestInfo`](multistore::route_handler::RequestInfo) required by the gateway.

use crate::body::JsBody;
use crate::response::headermap_from_js;
use http::{HeaderMap, Method, Uri};
use multistore::route_handler::RequestInfo;

/// Owned HTTP request metadata extracted from a `web_sys::Request`.
///
/// Workers passes a `web_sys::Request` with borrowed JS strings and a
/// `ReadableStream` body.  The gateway expects a [`RequestInfo`] that
/// borrows from Rust-owned data, so this struct bridges the gap by
/// owning the parsed method, path, query, and headers.
///
/// # Example
///
/// ```rust,ignore
/// let (parts, body) = RequestParts::from_web_sys(&req)?;
/// let result = gateway
///     .handle_request(&parts.as_request_info(), body, collect_js_body)
///     .await;
/// ```
pub struct RequestParts {
    /// The HTTP method.
    pub method: Method,
    /// The URL path (e.g. `"/bucket/key"`).
    pub path: String,
    /// The raw query string, if present.
    pub query: Option<String>,
    /// The HTTP request headers.
    pub headers: HeaderMap,
}

impl RequestParts {
    /// Parse a `web_sys::Request` into owned request metadata and a
    /// zero-copy [`JsBody`].
    ///
    /// Extracts the body stream **before** reading headers, so the
    /// `ReadableStream` is never locked.
    pub fn from_web_sys(req: &web_sys::Request) -> Result<(Self, JsBody), String> {
        let body = JsBody::new(req.body());

        let method: Method = req
            .method()
            .parse()
            .map_err(|e| format!("invalid method: {e}"))?;

        let uri: Uri = req.url().parse().map_err(|e| format!("invalid URL: {e}"))?;

        let path = uri.path().to_string();
        let query = uri.query().map(|q| q.to_string());
        let headers = headermap_from_js(&req.headers());

        Ok((
            Self {
                method,
                path,
                query,
                headers,
            },
            body,
        ))
    }

    /// Borrow this struct as a [`RequestInfo`] for gateway dispatch.
    pub fn as_request_info(&self) -> RequestInfo<'_> {
        RequestInfo::new(
            &self.method,
            &self.path,
            self.query.as_deref(),
            &self.headers,
            None,
        )
    }
}
