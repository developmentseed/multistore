//! Hierarchical path mapping for the multistore S3 proxy gateway.
//!
//! This crate provides [`PathMapping`] for translating hierarchical URL paths
//! (e.g., `/{account}/{product}/{key}`) into flat internal bucket names
//! (e.g., `account--product`), and [`MappedRegistry`] for wrapping a
//! [`BucketRegistry`] so that path-based routing and list rewrite rules are
//! applied automatically.

use multistore::api::list_rewrite::ListRewrite;
use multistore::registry::{BucketRegistry, ResolvedBucket};

/// Defines how URL path segments map to internal bucket names.
#[derive(Debug, Clone)]
pub struct PathMapping {
    /// Number of path segments that form the "bucket" portion.
    /// E.g., 2 for `/{account}/{product}/...`
    pub bucket_segments: usize,

    /// Separator to join segments into an internal bucket name.
    /// E.g., "--" produces `account--product`.
    pub bucket_separator: String,

    /// How many leading segments form the "display bucket" name for XML responses.
    /// E.g., 1 means `<Name>` shows just `account`.
    pub display_bucket_segments: usize,
}

/// Result of mapping a request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedPath {
    /// Internal bucket name (e.g., "account--product")
    pub bucket: String,
    /// Remaining key after bucket segments (e.g., "file.parquet")
    pub key: Option<String>,
    /// Display bucket name for XML responses (e.g., "account")
    pub display_bucket: String,
    /// Key prefix to add in XML responses (e.g., "product/")
    pub key_prefix: String,
    /// The individual path segments that formed the bucket
    pub segments: Vec<String>,
}

impl PathMapping {
    /// Parse a URL path into a `MappedPath`.
    ///
    /// The path is expected to start with `/`. Segments are split on `/`,
    /// and the first `bucket_segments` segments form the internal bucket name.
    /// Any remaining content becomes the key.
    ///
    /// Returns `None` if there are fewer than `bucket_segments` non-empty segments.
    pub fn parse(&self, path: &str) -> Option<MappedPath> {
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        if trimmed.is_empty() {
            return None;
        }

        // Split into at most bucket_segments + 1 parts so the key portion
        // preserves any internal `/` characters.
        let parts: Vec<&str> = trimmed.splitn(self.bucket_segments + 1, '/').collect();

        if parts.len() < self.bucket_segments {
            return None;
        }

        // Verify none of the bucket segments are empty.
        for part in &parts[..self.bucket_segments] {
            if part.is_empty() {
                return None;
            }
        }

        let segments: Vec<String> = parts[..self.bucket_segments]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let bucket = segments.join(&self.bucket_separator);

        let key = if parts.len() > self.bucket_segments {
            let k = parts[self.bucket_segments];
            if k.is_empty() {
                None
            } else {
                Some(k.to_string())
            }
        } else {
            None
        };

        let display_bucket = segments[..self.display_bucket_segments].join("/");

        let key_prefix = if self.display_bucket_segments < self.bucket_segments {
            let prefix_parts = &segments[self.display_bucket_segments..self.bucket_segments];
            format!("{}/", prefix_parts.join("/"))
        } else {
            String::new()
        };

        Some(MappedPath {
            bucket,
            key,
            display_bucket,
            key_prefix,
            segments,
        })
    }

    /// Parse a bucket name (e.g., "account--product") back into a `MappedPath`.
    ///
    /// Used by `MappedRegistry` when it receives an already-mapped bucket name.
    /// Returns `None` if the bucket name does not split into exactly `bucket_segments` parts.
    pub fn parse_bucket_name(&self, bucket_name: &str) -> Option<MappedPath> {
        let segments: Vec<String> = bucket_name
            .split(&self.bucket_separator)
            .map(|s| s.to_string())
            .collect();

        if segments.len() != self.bucket_segments {
            return None;
        }

        // Verify none of the segments are empty.
        for seg in &segments {
            if seg.is_empty() {
                return None;
            }
        }

        let display_bucket = segments[..self.display_bucket_segments].join("/");

        let key_prefix = if self.display_bucket_segments < self.bucket_segments {
            let prefix_parts = &segments[self.display_bucket_segments..self.bucket_segments];
            format!("{}/", prefix_parts.join("/"))
        } else {
            String::new()
        };

        Some(MappedPath {
            bucket: bucket_name.to_string(),
            key: None,
            display_bucket,
            key_prefix,
            segments,
        })
    }
}

/// Wraps a `BucketRegistry` to add path-based routing.
///
/// When `get_bucket` is called, the bucket name is parsed via
/// `PathMapping::parse_bucket_name` and the resulting `ListRewrite`
/// and `display_name` are applied to the resolved bucket.
#[derive(Debug, Clone)]
pub struct MappedRegistry<R> {
    inner: R,
    mapping: PathMapping,
}

impl<R> MappedRegistry<R> {
    /// Create a new `MappedRegistry` wrapping the given registry with a path mapping.
    pub fn new(inner: R, mapping: PathMapping) -> Self {
        Self { inner, mapping }
    }
}

impl<R: BucketRegistry> BucketRegistry for MappedRegistry<R> {
    async fn get_bucket(
        &self,
        name: &str,
        identity: &multistore::types::ResolvedIdentity,
        operation: &multistore::types::S3Operation,
    ) -> Result<ResolvedBucket, multistore::error::ProxyError> {
        let mapped = self.mapping.parse_bucket_name(name);

        let mut resolved = self.inner.get_bucket(name, identity, operation).await?;

        if let Some(mapped) = mapped {
            tracing::debug!(
                bucket = %name,
                display_name = %mapped.display_bucket,
                key_prefix = %mapped.key_prefix,
                "Applying path mapping to resolved bucket"
            );

            resolved.display_name = Some(mapped.display_bucket);

            if !mapped.key_prefix.is_empty() {
                resolved.list_rewrite = Some(ListRewrite {
                    strip_prefix: String::new(),
                    add_prefix: mapped.key_prefix,
                });
            }
        }

        Ok(resolved)
    }

    async fn list_buckets(
        &self,
        identity: &multistore::types::ResolvedIdentity,
    ) -> Result<Vec<multistore::api::response::BucketEntry>, multistore::error::ProxyError> {
        self.inner.list_buckets(identity).await
    }

    fn bucket_owner(&self) -> multistore::types::BucketOwner {
        self.inner.bucket_owner()
    }
}
