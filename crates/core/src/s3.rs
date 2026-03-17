//! Built-in S3 request processing middleware.
//!
//! This module provides middleware that handles S3 request parsing, identity
//! resolution, and bucket authorization. These can be used individually for
//! fine-grained control or combined via [`S3RequestMiddleware`].
//!
//! ## Individual middleware
//!
//! - [`S3OpParser`] -- parses the S3 operation from the HTTP request
//! - [`AuthMiddleware`] -- resolves caller identity from SigV4 headers
//! - [`BucketResolver`] -- looks up bucket configuration and authorizes access
//!
//! ## Combined middleware
//!
//! [`S3RequestMiddleware`] runs all three steps in sequence for convenience.

use crate::api::request::{self, HostStyle};
use crate::api::response::BucketEntry;
use crate::auth;
use crate::auth::TemporaryCredentialResolver;
use crate::error::ProxyError;
use crate::middleware::{Middleware, Next, RequestContext};
use crate::registry::{BucketRegistry, CredentialRegistry};
use crate::route_handler::HandlerAction;
use crate::types::{BucketOwner, ResolvedIdentity, S3Operation};
use http::HeaderMap;

// ---------------------------------------------------------------------------
// Host style detection
// ---------------------------------------------------------------------------

/// Determine whether the request uses path-style or virtual-hosted-style
/// bucket addressing based on the `Host` header and the configured domain.
pub(crate) fn determine_host_style(
    headers: &HeaderMap,
    virtual_host_domain: Option<&str>,
) -> HostStyle {
    if let Some(domain) = virtual_host_domain {
        if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
            let host = host.split(':').next().unwrap_or(host);
            if let Some(bucket) = host.strip_suffix(&format!(".{}", domain)) {
                return HostStyle::VirtualHosted {
                    bucket: bucket.to_string(),
                };
            }
        }
    }
    HostStyle::Path
}

// ---------------------------------------------------------------------------
// Extension type for ListBuckets data
// ---------------------------------------------------------------------------

/// Data inserted into extensions by [`BucketResolver`] for `ListBuckets` operations.
///
/// Since the bucket registry is owned by the middleware, dispatch needs this
/// extension to build the ListBuckets XML response.
#[derive(Clone)]
pub struct ResolvedBucketList {
    /// The bucket entries visible to the caller.
    pub buckets: Vec<BucketEntry>,
    /// The owner identity for the response XML.
    pub owner: BucketOwner,
}

// ---------------------------------------------------------------------------
// S3OpParser
// ---------------------------------------------------------------------------

/// Middleware that parses the incoming HTTP request into a typed S3 operation.
///
/// Inserts into extensions:
/// - [`S3Operation`]
/// - [`HostStyle`]
pub struct S3OpParser {
    virtual_host_domain: Option<String>,
}

impl S3OpParser {
    /// Create a new S3 operation parser.
    ///
    /// `virtual_host_domain` enables virtual-hosted-style bucket addressing
    /// (e.g., `bucket.s3.example.com`).
    pub fn new(virtual_host_domain: Option<String>) -> Self {
        Self {
            virtual_host_domain,
        }
    }
}

impl Middleware for S3OpParser {
    async fn handle<'a>(
        &'a self,
        mut ctx: RequestContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        let host_style = determine_host_style(ctx.headers, self.virtual_host_domain.as_deref());
        ctx.extensions.insert(host_style.clone());

        let operation =
            request::parse_s3_request(ctx.method, ctx.path, ctx.query, ctx.headers, host_style)?;
        tracing::debug!(operation = ?operation, "parsed S3 operation");
        ctx.extensions.insert(operation.clone());

        next.run(ctx).await
    }
}

// ---------------------------------------------------------------------------
// AuthMiddleware
// ---------------------------------------------------------------------------

/// Middleware that resolves the caller's identity from SigV4 headers.
///
/// Inserts into extensions:
/// - [`ResolvedIdentity`]
pub struct AuthMiddleware<C> {
    credential_registry: C,
    credential_resolver: Option<Box<dyn TemporaryCredentialResolver>>,
}

impl<C> AuthMiddleware<C> {
    /// Create a new auth middleware with the given credential registry.
    pub fn new(credential_registry: C) -> Self {
        Self {
            credential_registry,
            credential_resolver: None,
        }
    }

    /// Set the temporary credential resolver for session token verification.
    pub fn with_credential_resolver(
        mut self,
        resolver: impl TemporaryCredentialResolver + 'static,
    ) -> Self {
        self.credential_resolver = Some(Box::new(resolver));
        self
    }
}

impl<C: CredentialRegistry> Middleware for AuthMiddleware<C> {
    async fn handle<'a>(
        &'a self,
        mut ctx: RequestContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        let identity = auth::resolve_identity(
            ctx.method,
            ctx.path,
            ctx.query.unwrap_or(""),
            ctx.headers,
            &self.credential_registry,
            self.credential_resolver.as_deref(),
        )
        .await?;
        tracing::debug!(identity = ?identity, "resolved identity");
        ctx.extensions.insert(identity);

        next.run(ctx).await
    }
}

// ---------------------------------------------------------------------------
// BucketResolver
// ---------------------------------------------------------------------------

/// Middleware that resolves bucket configuration and authorizes access.
///
/// Reads [`S3Operation`] and [`ResolvedIdentity`] from extensions (returns
/// an error if they are missing). For bucket-targeted operations, inserts
/// [`ResolvedBucket`](crate::registry::ResolvedBucket). For `ListBuckets`,
/// inserts [`ResolvedBucketList`].
pub struct BucketResolver<R> {
    bucket_registry: R,
}

impl<R> BucketResolver<R> {
    /// Create a new bucket resolver with the given bucket registry.
    pub fn new(bucket_registry: R) -> Self {
        Self { bucket_registry }
    }
}

impl<R: BucketRegistry> Middleware for BucketResolver<R> {
    async fn handle<'a>(
        &'a self,
        mut ctx: RequestContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        let operation = ctx
            .operation()
            .ok_or_else(|| {
                ProxyError::Internal(
                    "S3Operation not in context -- is S3OpParser middleware registered?".into(),
                )
            })?
            .clone();

        let identity = ctx
            .identity()
            .cloned()
            .unwrap_or(ResolvedIdentity::Anonymous);

        if let Some(bucket_name) = operation.bucket() {
            let resolved = self
                .bucket_registry
                .get_bucket(bucket_name, &identity, &operation)
                .await?;
            tracing::debug!(
                bucket = %bucket_name,
                backend_type = %resolved.config.backend_type,
                "resolved bucket config"
            );
            ctx.extensions.insert(resolved);
        } else if matches!(operation, S3Operation::ListBuckets) {
            // For ListBuckets, resolve the bucket list so dispatch can build the response.
            let buckets = self.bucket_registry.list_buckets(&identity).await?;
            let owner = self.bucket_registry.bucket_owner();
            ctx.extensions.insert(ResolvedBucketList { buckets, owner });
        }

        next.run(ctx).await
    }
}

// ---------------------------------------------------------------------------
// S3RequestMiddleware (combined convenience)
// ---------------------------------------------------------------------------

/// Combined S3 request middleware: parses the operation, resolves identity,
/// looks up bucket config, and authorizes.
///
/// This is a convenience wrapper around [`S3OpParser`], [`AuthMiddleware`],
/// and [`BucketResolver`]. For maximum flexibility, register them individually.
///
/// Inserts into extensions:
/// - [`S3Operation`]
/// - [`HostStyle`]
/// - [`ResolvedIdentity`]
/// - [`ResolvedBucket`](crate::registry::ResolvedBucket) (if operation targets a bucket)
/// - [`ResolvedBucketList`] (if operation is `ListBuckets`)
pub struct S3RequestMiddleware<R, C> {
    bucket_registry: R,
    credential_registry: C,
    credential_resolver: Option<Box<dyn TemporaryCredentialResolver>>,
    virtual_host_domain: Option<String>,
}

impl<R, C> S3RequestMiddleware<R, C> {
    /// Create a new combined S3 request middleware.
    pub fn new(
        bucket_registry: R,
        credential_registry: C,
        virtual_host_domain: Option<String>,
    ) -> Self {
        Self {
            bucket_registry,
            credential_registry,
            credential_resolver: None,
            virtual_host_domain,
        }
    }

    /// Set the temporary credential resolver for session token verification.
    pub fn with_credential_resolver(
        mut self,
        resolver: impl TemporaryCredentialResolver + 'static,
    ) -> Self {
        self.credential_resolver = Some(Box::new(resolver));
        self
    }
}

impl<R: BucketRegistry, C: CredentialRegistry> Middleware for S3RequestMiddleware<R, C> {
    async fn handle<'a>(
        &'a self,
        mut ctx: RequestContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        // 1. Determine host style
        let host_style = determine_host_style(ctx.headers, self.virtual_host_domain.as_deref());
        ctx.extensions.insert(host_style.clone());

        // 2. Parse S3 operation
        let operation =
            request::parse_s3_request(ctx.method, ctx.path, ctx.query, ctx.headers, host_style)?;
        tracing::debug!(operation = ?operation, "parsed S3 operation");
        ctx.extensions.insert(operation.clone());

        // 3. Resolve identity
        let identity = auth::resolve_identity(
            ctx.method,
            ctx.path,
            ctx.query.unwrap_or(""),
            ctx.headers,
            &self.credential_registry,
            self.credential_resolver.as_deref(),
        )
        .await?;
        tracing::debug!(identity = ?identity, "resolved identity");
        ctx.extensions.insert(identity.clone());

        // 4. Resolve bucket config (if operation targets a bucket)
        if let Some(bucket_name) = operation.bucket() {
            let resolved = self
                .bucket_registry
                .get_bucket(bucket_name, &identity, &operation)
                .await?;
            tracing::debug!(
                bucket = %bucket_name,
                backend_type = %resolved.config.backend_type,
                "resolved bucket config"
            );
            ctx.extensions.insert(resolved);
        } else if matches!(operation, S3Operation::ListBuckets) {
            let buckets = self.bucket_registry.list_buckets(&identity).await?;
            let owner = self.bucket_registry.bucket_owner();
            ctx.extensions.insert(ResolvedBucketList { buckets, owner });
        }

        next.run(ctx).await
    }
}
