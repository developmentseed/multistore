//! Cloudflare Workers runtime adapters for the multistore S3 proxy gateway.
//!
//! This crate provides reusable runtime primitives for running a multistore
//! proxy on Cloudflare Workers:
//!
//! - [`FetchConnector`] — `object_store::client::HttpConnector` using the Fetch API
//! - [`JsBody`] — zero-copy body wrapper around `web_sys::ReadableStream`
//! - [`WorkerBackend`] — `ProxyBackend` implementation using the Fetch API
//! - [`WorkerSubscriber`] — `tracing::Subscriber` routing to `console.log`
//! - [`NoopCredentialRegistry`] — anonymous-only credential registry
//! - Response helpers for building `web_sys::Response` from proxy results

pub mod backend;
pub mod body;
pub mod fetch_connector;
pub mod noop_creds;
pub mod response;
pub mod tracing_layer;

pub use backend::WorkerBackend;
pub use body::{collect_js_body, JsBody};
pub use fetch_connector::FetchConnector;
pub use noop_creds::NoopCredentialRegistry;
pub use response::{
    convert_ws_headers, forward_response_to_ws, http_headermap_to_ws_headers,
    proxy_result_to_ws_response, ws_error_response, ws_xml_response,
};
pub use tracing_layer::WorkerSubscriber;
