//! # multistore
//!
//! Runtime-agnostic core library for the S3 proxy gateway.
//!
//! This crate provides the s3s-based S3 service implementation that maps
//! S3 API operations to `object_store` calls, along with the trait
//! abstractions that allow it to run on multiple runtimes (Tokio/Hyper,
//! AWS Lambda, Cloudflare Workers).
//!
//! ## Key Abstractions
//!
//! - [`service::MultistoreService`] — s3s-based S3 service (maps S3 ops → object_store)
//! - [`service::MultistoreAuth`] — s3s auth provider (delegates to `CredentialRegistry`)
//! - [`service::StoreFactory`] — runtime-provided factory for creating object stores per request
//! - [`registry::BucketRegistry`] — bucket lookup, authorization, and listing
//! - [`registry::CredentialRegistry`] — credential and role storage
//! - [`auth::TemporaryCredentialResolver`] — resolve session tokens into temporary credentials
//! - [`backend::StoreBuilder`] — provider-agnostic object store builder
//! - [`api::response`] — S3 XML response serialization

pub mod api;
pub mod auth;
pub mod backend;
pub mod error;
pub mod maybe_send;
pub mod registry;
pub mod service;
pub mod types;
