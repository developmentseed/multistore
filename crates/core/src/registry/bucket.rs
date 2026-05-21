//! Bucket registry trait for resolving and listing virtual buckets.

use crate::api::list_rewrite::ListRewrite;
use crate::api::response::BucketEntry;
use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::types::{BucketConfig, BucketOwner, ResolvedIdentity, S3Operation};
use std::future::Future;

/// Default owner name used in `ListAllMyBucketsResult` responses.
pub const DEFAULT_BUCKET_OWNER: &str = "multistore-proxy";

/// The result of resolving a bucket from the registry.
///
/// Contains the backend configuration needed to proxy the request,
/// plus any optional list rewrite rules.
pub struct ResolvedBucket {
    /// Backend configuration for this bucket.
    pub config: BucketConfig,
    /// Optional rewrite rule for list response XML.
    pub list_rewrite: Option<ListRewrite>,
    /// Optional display name for the bucket, used in LIST responses.
    ///
    /// When set, this name is used in the `<Name>` element of
    /// `ListBucketResult` XML instead of the backend bucket name.
    pub display_name: Option<String>,
}

/// Trait for resolving virtual buckets and authorizing access.
///
/// Implementations encapsulate bucket lookup, namespace mapping, and
/// authorization logic. The proxy gateway calls these methods after
/// parsing the S3 request and resolving the caller's identity.
///
/// Implementations should be cheap to clone (wrap inner state in `Arc`).
pub trait BucketRegistry: Clone + MaybeSend + MaybeSync + 'static {
    /// Resolve a bucket by name, checking authorization for the given identity and operation.
    ///
    /// Returns `Err(ProxyError::BucketNotFound)` if the bucket doesn't exist,
    /// or `Err(ProxyError::AccessDenied)` if the identity lacks access.
    fn get_bucket(
        &self,
        name: &str,
        identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> impl Future<Output = Result<ResolvedBucket, ProxyError>> + MaybeSend;

    /// List all buckets visible to the given identity.
    fn list_buckets(
        &self,
        identity: &ResolvedIdentity,
    ) -> impl Future<Output = Result<Vec<BucketEntry>, ProxyError>> + MaybeSend;

    /// The owner identity returned in `ListAllMyBucketsResult` responses.
    ///
    /// Defaults to `("multistore-proxy", "multistore-proxy")`.
    fn bucket_owner(&self) -> BucketOwner {
        BucketOwner {
            id: DEFAULT_BUCKET_OWNER.to_string(),
            display_name: DEFAULT_BUCKET_OWNER.to_string(),
        }
    }
}
