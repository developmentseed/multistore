//! XML rewriting for S3 list responses.
//!
//! When a backend prefix is configured, the backend returns keys that include
//! the prefix. This module strips that prefix and optionally prepends a new
//! one, so clients see the expected key structure.

/// Describes how to rewrite `<Key>` and `<Prefix>` values in list response XML.
#[derive(Debug, Clone)]
pub struct ListRewrite {
    /// Prefix to strip from the beginning of values.
    pub strip_prefix: String,
    /// Prefix to add after stripping.
    pub add_prefix: String,
}
