//! Types for HTTP forwarding to backend object stores.
//!
//! The proxy core produces a [`ForwardRequest`] describing *what* to send;
//! the [`ProxyBackend::forward`](crate::backend::ProxyBackend::forward)
//! implementation decides *how* to send it and returns a [`ForwardResponse`]
//! with the backend's status, headers, and streaming body.

use http::HeaderMap;

// Re-export so downstream code can still reach it via `forwarder::ForwardRequest`.
pub use crate::route_handler::ForwardRequest;

/// The response returned after executing a backend request.
///
/// `S` is the streaming body type, which varies per runtime — for example,
/// a Hyper `Incoming` body on native targets or a Workers `ReadableStream`
/// on the edge.
pub struct ForwardResponse<S> {
    /// HTTP status code from the backend.
    pub status: u16,
    /// Response headers from the backend.
    pub headers: HeaderMap,
    /// The streaming response body.
    pub body: S,
    /// Content length reported by the backend, if known.
    pub content_length: Option<u64>,
}
