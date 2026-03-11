//! # s3-proxy-core
//!
//! Runtime-agnostic core library for the S3 proxy gateway.
//!
//! This crate defines the trait abstractions that allow the proxy to run on
//! multiple runtimes (Tokio/Hyper for containers, Cloudflare Workers for edge)
//! without either runtime leaking into the core logic.
//!
//! ## Key Abstractions
//!
//! - [`route_handler::ProxyResponseBody`] — concrete response body type (Stream, Bytes, Empty)
//! - [`backend::ProxyBackend`] — create object stores and send raw HTTP requests
//! - [`registry::BucketRegistry`] — bucket lookup, authorization, and listing
//! - [`registry::CredentialRegistry`] — credential and role storage
//! - [`auth`] — SigV4 request verification and credential resolution
//! - [`api::request`] — parse incoming S3 API requests into typed operations
//! - [`api::response`] — serialize S3 XML responses
//! - [`route_handler::RouteHandler`] — pluggable pre-dispatch request interception (OIDC, STS, etc.)
//! - [`middleware::Middleware`] — composable post-auth middleware for dispatch
//! - [`forwarder::Forwarder`] — runtime-agnostic HTTP forwarding for backend requests
//! - [`router::Router`] — path-based route matching via `matchit` for efficient dispatch
//! - [`proxy::ProxyGateway`] — the main request handler that ties everything together

pub mod api;
pub mod auth;
pub mod backend;
pub mod error;
pub mod forwarder;
pub mod maybe_send;
pub mod middleware;
pub mod proxy;
pub mod registry;
pub mod route_handler;
pub mod router;
pub mod types;
