//! Registry abstractions for bucket policy and credential storage.
//!
//! These traits separate two distinct concerns:
//!
//! - [`BucketRegistry`] — bucket lookup, authorization, and listing (product-specific policy)
//! - [`CredentialRegistry`] — credential and role storage (auth infrastructure)
//!
//! This split allows custom implementations to provide their own bucket
//! resolution logic (namespace mapping, per-request authorization, etc.)
//! without reimplementing S3 request parsing or credential verification.

mod bucket;
mod credential;

pub use bucket::{BucketRegistry, ResolvedBucket, DEFAULT_BUCKET_OWNER};
pub use credential::CredentialRegistry;
