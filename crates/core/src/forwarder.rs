//! Runtime-agnostic HTTP forwarding trait.
//!
//! The [`Forwarder`] trait abstracts over the HTTP client used to execute
//! presigned backend requests. Each runtime (Tokio/Hyper, Cloudflare Workers)
//! provides its own implementation that streams request and response bodies
//! using native primitives.
//!
//! The proxy core produces a [`ForwardRequest`] describing *what* to send;
//! the `Forwarder` implementation decides *how* to send it and returns a
//! [`ForwardResponse`] with the backend's status, headers, and streaming body.

use std::future::Future;

use http::HeaderMap;

use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::route_handler::ForwardRequest;

/// The response returned by a [`Forwarder`] after executing a backend request.
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

/// Executes a presigned [`ForwardRequest`] against the backend and returns
/// the response.
///
/// The trait is generic over `Body` (the request body type) because callers
/// may provide different body representations depending on the operation —
/// for example, a streaming upload body for PUT or an empty body for GET.
///
/// # Implementing
///
/// ```rust,ignore
/// struct HyperForwarder { client: hyper::Client<...> }
///
/// impl Forwarder<hyper::body::Incoming> for HyperForwarder {
///     type ResponseBody = hyper::body::Incoming;
///
///     async fn forward(
///         &self,
///         request: ForwardRequest,
///         body: hyper::body::Incoming,
///     ) -> Result<ForwardResponse<Self::ResponseBody>, ProxyError> {
///         // build and send the HTTP request using the native client
///         todo!()
///     }
/// }
/// ```
pub trait Forwarder<Body>: MaybeSend + MaybeSync + 'static {
    /// The streaming body type in the backend response.
    type ResponseBody: MaybeSend + 'static;

    /// Execute the given [`ForwardRequest`] with the provided body and return
    /// the backend's response.
    fn forward(
        &self,
        request: ForwardRequest,
        body: Body,
    ) -> impl Future<Output = Result<ForwardResponse<Self::ResponseBody>, ProxyError>> + MaybeSend;
}
