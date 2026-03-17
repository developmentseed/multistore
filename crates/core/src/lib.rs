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
//! - [`backend::ProxyBackend`] -- create object stores and send raw HTTP requests
//! - [`registry::BucketRegistry`] -- bucket lookup, authorization, and listing
//! - [`registry::CredentialRegistry`] -- credential and role storage
//! - [`middleware::Middleware`] -- composable middleware for the request pipeline
//! - [`middleware::RequestContext`] -- context that flows through the middleware chain,
//!   carrying request metadata and a typed extensions map for inter-middleware data sharing
//! - [`forwarder::Forwarder`] -- runtime-agnostic HTTP forwarding for backend requests
//! - [`proxy::ProxyGateway`] -- the main request handler that ties everything together
//!
//! ## Built-in Middleware
//!
//! - [`s3`] -- S3 request processing middleware ([`s3::S3OpParser`], [`s3::AuthMiddleware`],
//!   [`s3::BucketResolver`]) that parse the S3 operation, resolve caller identity, and
//!   authorize bucket access. Register via [`proxy::ProxyGateway::with_s3_defaults`].
//! - [`cors`] -- per-bucket CORS middleware ([`cors::CorsMiddleware`]) that handles
//!   preflight requests and stamps CORS headers on responses. Placed before auth so
//!   that `OPTIONS` requests succeed without credentials.
//! - [`router::Router`] -- path-based route matching via `matchit`, implements `Middleware`
//!   for inline route handling (STS, OIDC discovery, health checks, etc.).
//!
//! ## Request Pipeline
//!
//! All request processing flows through a unified middleware chain:
//!
//! ```text
//! Request -> [CorsMiddleware] -> [Router] -> [S3OpParser] -> [AuthMiddleware]
//!         -> [BucketResolver] -> [custom middleware...] -> dispatch
//! ```
//!
//! Each middleware receives a [`middleware::RequestContext`] and a [`middleware::Next`]
//! handle to continue the chain. Middleware can enrich the context, short-circuit with
//! an early response, or delegate to the next middleware.

pub mod api;
pub mod auth;
pub mod backend;
pub mod cors;
pub mod error;
pub mod forwarder;
pub mod maybe_send;
pub mod middleware;
pub mod proxy;
pub mod registry;
pub mod route_handler;
pub mod router;
pub mod s3;
pub mod types;
