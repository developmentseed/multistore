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
    /// The percent-**decoded** URL path (e.g. `"/bucket/my key"`).
    ///
    /// Decoded for S3 operation parsing and bucket/key routing. **Do not** use
    /// this for SigV4 verification: the canonical URI must be the encoded form
    /// the client signed, so use [`signing_path`](Self::signing_path) instead.
    pub path: String,
    /// The raw, percent-**encoded** URL path exactly as it arrived on the wire
    /// (e.g. `"/bucket/my%20key"`).
    ///
    /// This is the form the client signs, so it is what SigV4 verification must
    /// canonicalize over. [`as_request_info`](Self::as_request_info) wires it
    /// into [`RequestInfo`]'s signing path automatically. Integrators that
    /// rewrite paths before dispatch (e.g. path-mapping) must still sign against
    /// this encoded path — never the decoded [`path`](Self::path).
    pub signing_path: String,
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

        // `uri.path()` is the raw, percent-encoded path. Keep it verbatim for
        // SigV4 signing (the client signs the encoded form), and separately
        // decode it for operation parsing and bucket/key routing.
        let signing_path = uri.path().to_string();
        let path = percent_encoding::percent_decode_str(uri.path())
            .decode_utf8_lossy()
            .to_string();
        let query = uri.query().map(|q| q.to_string());
        let headers = headermap_from_js(&req.headers());

        Ok((
            Self {
                method,
                path,
                signing_path,
                query,
                headers,
            },
            body,
        ))
    }

    /// Borrow this struct as a [`RequestInfo`] for gateway dispatch.
    ///
    /// Sets the signing path to the raw, percent-encoded
    /// [`signing_path`](Self::signing_path) so SigV4 verification canonicalizes
    /// over the path the client actually signed. Without this, a key containing
    /// a character the client escapes — e.g. a space → `%20` — would be verified
    /// against the decoded path and fail with `SignatureDoesNotMatch`.
    pub fn as_request_info(&self) -> RequestInfo<'_> {
        RequestInfo::new(
            &self.method,
            &self.path,
            self.query.as_deref(),
            &self.headers,
            None,
        )
        .with_signing_path(&self.signing_path)
    }
}
