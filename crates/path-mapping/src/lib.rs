//! Hierarchical path mapping for the multistore S3 proxy gateway.
//!
//! S3 uses a flat namespace: each bucket is an independent container resolved
//! to a single backend. Some applications need a *hierarchical* URL scheme
//! where multiple path segments determine which backend to use. For example,
//! a data catalog might expose `/{account}/{product}/{key}` but store each
//! account/product pair in its own backend bucket.
//!
//! This crate bridges those two worlds:
//!
//! - **[`PathMapping`]** defines *how many* leading URL segments form the
//!   logical "bucket", what separator joins them into an internal name, and
//!   how many segments appear as the display name in S3 XML responses.
//!
//! - **[`PathMapping::rewrite_request`]** rewrites an incoming `(path, query)`
//!   pair so the gateway sees a single-segment bucket. It handles both
//!   path-based routing (`/{a}/{b}/{key}` → `/{a:b}/{key}`) and query-based
//!   prefix routing (`/{a}?prefix=b/sub/` → `/{a:b}?prefix=sub/`).
//!
//! - **[`MappedRegistry`]** wraps any [`BucketRegistry`] and automatically
//!   applies display-name and list-rewrite rules so XML responses show the
//!   original hierarchical names to clients.
//!
//! # Example
//!
//! ```rust
//! use multistore_path_mapping::PathMapping;
//!
//! let mapping = PathMapping {
//!     bucket_segments: 2,
//!     bucket_separator: ":".into(),
//!     display_bucket_segments: 1,
//! };
//!
//! // Path-based: two segments become one internal bucket
//! let mapped = mapping.parse("/acme/data/report.csv").unwrap();
//! assert_eq!(mapped.bucket, "acme:data");
//! assert_eq!(mapped.key, Some("report.csv".to_string()));
//! assert_eq!(mapped.display_bucket, "acme");
//!
//! // Full request rewrite (path + query)
//! let (path, query) = mapping.rewrite_request(
//!     "/acme/data/report.csv",
//!     None,
//! );
//! assert_eq!(path, "/acme:data/report.csv");
//! assert_eq!(query, None);
//!
//! // Prefix-based list rewrite
//! let (path, query) = mapping.rewrite_request(
//!     "/acme",
//!     Some("list-type=2&prefix=data/subdir/"),
//! );
//! assert_eq!(path, "/acme:data");
//! assert_eq!(query, Some("list-type=2&prefix=subdir/".to_string()));
//! ```

use multistore::api::list_rewrite::ListRewrite;
use multistore::registry::{BucketRegistry, ResolvedBucket};

/// Defines how URL path segments map to internal bucket names.
#[derive(Debug, Clone)]
pub struct PathMapping {
    /// Number of path segments that form the "bucket" portion.
    /// E.g., 2 for `/{account}/{product}/...`
    pub bucket_segments: usize,

    /// Separator to join segments into an internal bucket name.
    /// E.g., ":" produces `account:product`.
    pub bucket_separator: String,

    /// How many leading segments form the "display bucket" name for XML responses.
    /// E.g., 1 means `<Name>` shows just `account`.
    pub display_bucket_segments: usize,
}

/// Result of mapping a request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedPath {
    /// Internal bucket name (e.g., "account:product")
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
    /// Parse a URL path into a [`MappedPath`].
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

    /// Parse a bucket name (e.g., "account:product") back into a [`MappedPath`].
    ///
    /// Used by [`MappedRegistry`] when it receives an already-mapped bucket name.
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

    /// Rewrite an incoming request path and query string for the gateway.
    ///
    /// Translates hierarchical paths into internal single-segment bucket paths:
    ///
    /// 1. **Path-based**: if the path has enough segments, they are joined into
    ///    a single bucket name.
    ///    `/{a}/{b}/{key}` → `/{a:b}/{key}`
    ///
    /// 2. **Prefix-based**: if the path has fewer segments than required but the
    ///    query string contains a `list-type=` param with a non-empty `prefix=`,
    ///    the first component of the prefix is folded into the bucket name.
    ///    `/{a}?list-type=2&prefix=b/sub/` → `/{a:b}?list-type=2&prefix=sub/`
    ///
    /// 3. **Pass-through**: all other paths are returned unchanged. Route handlers
    ///    or the gateway itself will handle them.
    pub fn rewrite_request(&self, path: &str, query: Option<&str>) -> (String, Option<String>) {
        // Case 1: enough path segments to map directly
        if let Some(mapped) = self.parse(path) {
            let rewritten_path = match mapped.key {
                Some(ref key) => format!("/{}/{}", mapped.bucket, key),
                None => format!("/{}", mapped.bucket),
            };
            return (rewritten_path, query.map(|q| q.to_string()));
        }

        // Case 2: single-segment path with a list-type query and non-empty prefix
        let trimmed = path.trim_matches('/');
        if !trimmed.is_empty() && !trimmed.contains('/') {
            let query_str = query.unwrap_or("");
            if is_list_request(query_str) {
                if let Some(prefix) = extract_query_param(query_str, "prefix") {
                    if !prefix.is_empty() {
                        return self.rewrite_prefix_to_bucket(trimmed, &prefix, query_str);
                    }
                }
            }
        }

        // Case 3: pass through unchanged
        (path.to_string(), query.map(|q| q.to_string()))
    }

    /// Fold the first prefix component into the bucket name.
    ///
    /// `/{account}?prefix=product/sub/` → `/{account:product}?prefix=sub/`
    fn rewrite_prefix_to_bucket(
        &self,
        account: &str,
        prefix: &str,
        query_str: &str,
    ) -> (String, Option<String>) {
        let (product, remaining_prefix) = if let Some(slash_pos) = prefix.find('/') {
            (&prefix[..slash_pos], &prefix[slash_pos + 1..])
        } else {
            (prefix, "")
        };

        let bucket = format!("{}{}{}", account, self.bucket_separator, product);
        let new_query = rewrite_prefix_in_query(query_str, remaining_prefix);
        (format!("/{}", bucket), Some(new_query))
    }
}

// ── Query-string helpers (private) ──────────────────────────────────

/// Check whether a query string contains a `list-type=` parameter.
fn is_list_request(query: &str) -> bool {
    query.split('&').any(|p| p.starts_with("list-type="))
}

/// Extract and percent-decode a single query parameter value.
fn extract_query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| {
                percent_encoding::percent_decode_str(v)
                    .decode_utf8_lossy()
                    .into_owned()
            })
    })
}

/// Characters that must be percent-encoded when placed in a query parameter value.
const QUERY_VALUE_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'#')
    .add(b'&')
    .add(b'=')
    .add(b'+');

/// Replace the `prefix=` value in a query string, percent-encoding the new value.
fn rewrite_prefix_in_query(query: &str, new_prefix: &str) -> String {
    let encoded: String =
        percent_encoding::utf8_percent_encode(new_prefix, QUERY_VALUE_ENCODE).to_string();
    query
        .split('&')
        .map(|pair| {
            if pair.starts_with("prefix=") {
                format!("prefix={}", encoded)
            } else {
                pair.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_list_request_detects_list_type() {
        assert!(is_list_request("list-type=2"));
        assert!(is_list_request("foo=bar&list-type=2&baz=qux"));
        assert!(!is_list_request("foo=bar"));
        assert!(!is_list_request(""));
    }

    #[test]
    fn is_list_request_rejects_substring_match() {
        assert!(!is_list_request("not-list-type=2"));
        assert!(!is_list_request("foo=bar&not-list-type=2"));
    }

    #[test]
    fn extract_query_param_finds_value() {
        assert_eq!(
            extract_query_param("list-type=2&prefix=foo/", "prefix"),
            Some("foo/".to_string())
        );
    }

    #[test]
    fn extract_query_param_missing() {
        assert_eq!(extract_query_param("list-type=2", "prefix"), None);
    }

    #[test]
    fn extract_query_param_decodes_percent() {
        assert_eq!(
            extract_query_param("prefix=hello%20world", "prefix"),
            Some("hello world".to_string())
        );
    }

    #[test]
    fn rewrite_prefix_replaces_value() {
        assert_eq!(
            rewrite_prefix_in_query("list-type=2&prefix=old/", "new/"),
            "list-type=2&prefix=new/"
        );
    }

    #[test]
    fn rewrite_prefix_to_empty() {
        assert_eq!(
            rewrite_prefix_in_query("prefix=old/&max-keys=100", ""),
            "prefix=&max-keys=100"
        );
    }

    #[test]
    fn rewrite_prefix_encodes_special_chars() {
        assert_eq!(
            rewrite_prefix_in_query("list-type=2&prefix=old/", "sub dir/"),
            "list-type=2&prefix=sub%20dir/"
        );
    }
}

// ── MappedRegistry ──────────────────────────────────────────────────

/// Wraps a [`BucketRegistry`] to add path-based routing.
///
/// When `get_bucket` is called, the bucket name is parsed via
/// [`PathMapping::parse_bucket_name`] and the resulting [`ListRewrite`]
/// and `display_name` are applied to the resolved bucket. This allows the
/// gateway to present hierarchical names in S3 XML responses while storing
/// data in flat internal buckets.
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
