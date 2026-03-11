//! Tokio/hyper runtime for the S3 proxy server.
//!
//! This crate provides concrete implementations of the core traits for a
//! standard server environment using Tokio and hyper.
//!
//! - [`client::ServerBackend`] — implements `StoreFactory` using reqwest + object_store
//! - [`server::run`] — starts the hyper HTTP server with s3s

pub mod cached;
pub mod client;
pub mod server;
