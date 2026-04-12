//! Cloudflare Workers runtime adapters for the multistore S3 proxy gateway.
//!
//! This crate provides reusable runtime primitives for running a multistore
//! proxy on Cloudflare Workers:
//!
//! - `FetchConnector` — `object_store::client::HttpConnector` using the Fetch API
//! - [`JsBody`] — zero-copy body wrapper around `web_sys::ReadableStream`
//! - [`WorkerBackend`] — `ProxyBackend` implementation using the Fetch API
//! - [`WorkerSubscriber`] — `tracing::Subscriber` routing to `console.log`
//! - [`NoopCredentialRegistry`] — anonymous-only credential registry
//! - [`response`] — helpers for building `web_sys::Response` from proxy results

pub(crate) mod fetch_connector;

pub mod backend;
pub mod body;
pub mod headers;
pub mod noop_creds;
pub mod request;
pub mod response;
pub mod tracing_layer;

pub use backend::WorkerBackend;
pub use body::{collect_js_body, JsBody};
pub use headers::WsHeaders;
pub use noop_creds::NoopCredentialRegistry;
pub use request::RequestParts;
pub use response::{headermap_from_js, response_from_gateway};
pub use tracing_layer::WorkerSubscriber;
