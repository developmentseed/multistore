//! The main proxy gateway that ties together registry lookup and backend forwarding.
//!
//! [`ProxyGateway`] is generic over the runtime's backend, bucket registry,
//! credential registry, and backend auth.
//!
//! ## Router (pre-dispatch)
//!
//! A [`Router`] maps URL path patterns to [`RouteHandler`](crate::route_handler::RouteHandler)
//! implementations using `matchit` for efficient matching. Exact paths take
//! priority over catch-all patterns, so OIDC discovery endpoints are matched
//! before a catch-all STS handler. Extension crates provide `Router` extension
//! traits for one-call registration.
//!
//! ## Proxy dispatch (two-phase)
//!
//! If no route handler matches, the request enters the two-phase pipeline:
//!
//! 1. **`resolve_request`** — parses the S3 operation, resolves identity,
//!    authorizes via the bucket registry, and decides the action:
//!    - GET/HEAD/PUT/DELETE → [`HandlerAction::Forward`] with a presigned URL
//!    - LIST → [`HandlerAction::Response`] with XML body
//!    - Multipart → [`HandlerAction::NeedsBody`] (body required)
//!    - Errors/synthetic → [`HandlerAction::Response`]
//!
//! 2. **`handle_with_body`** — completes multipart operations once the body arrives.
//!
//! ## Runtime integration
//!
//! The recommended entry point is [`ProxyGateway::handle_request`], which returns a
//! two-variant [`GatewayResponse<B>`]:
//!
//! - **`Response`** — a fully formed response to send to the client
//! - **`Forward`** — a presigned URL plus the original body for zero-copy streaming
//!
//! `NeedsBody` is resolved internally via a caller-provided body collection
//! closure, so runtimes only need a two-arm match:
//!
//! ```rust,ignore
//! match gateway.handle_request(&req_info, body, |b| to_bytes(b)).await {
//!     GatewayResponse::Response(result) => build_response(result),
//!     GatewayResponse::Forward(fwd, body) => forward(fwd, body).await,
//! }
//! ```
//!
//! For lower-level control, use [`ProxyGateway::handle`] which returns the
//! three-variant [`HandlerAction`] directly.

use crate::api::list::{build_list_prefix, build_list_xml, parse_list_query_params, ListXmlParams};
use crate::api::list_rewrite::ListRewrite;
use crate::api::request::{self, HostStyle};
use crate::api::response::{BucketList, ErrorResponse, ListAllMyBucketsResult};
use crate::auth;
use crate::auth::TemporaryCredentialResolver;
use crate::backend::auth::{BackendAuth, NoAuth};
use crate::backend::multipart::{build_backend_url, sign_s3_request};
use crate::backend::request_signer::{hash_payload, UNSIGNED_PAYLOAD};
use crate::backend::ProxyBackend;
use crate::error::ProxyError;
use crate::registry::{BucketRegistry, CredentialRegistry};
use crate::route_handler::{ProxyResponseBody, RequestInfo};
use crate::router::Router;
use crate::types::{BucketConfig, S3Operation};
use bytes::Bytes;
use http::{HeaderMap, Method};
use object_store::list::PaginatedListOptions;
use std::borrow::Cow;
use std::time::Duration;
use uuid::Uuid;

/// TTL for presigned URLs. Short because they're used immediately.
const PRESIGNED_URL_TTL: Duration = Duration::from_secs(300);

// Re-export types that were historically defined here for backwards compatibility.
pub use crate::route_handler::{
    ForwardRequest, HandlerAction, PendingRequest, ProxyResult, RESPONSE_HEADER_ALLOWLIST,
};

/// Simplified two-variant result from [`ProxyGateway::handle_request`].
///
/// The gateway resolves `NeedsBody` internally via the body collection
/// closure, so runtimes only need to handle `Response` and `Forward`.
/// The body type `B` is generic — `Forward` passes it through untouched
/// for zero-copy streaming.
pub enum GatewayResponse<B> {
    /// A fully formed response ready to send to the client.
    Response(ProxyResult),
    /// A presigned URL for the runtime to forward, with the original body
    /// for streaming (e.g. PUT uploads).
    Forward(ForwardRequest, B),
}

/// The core proxy gateway, generic over runtime primitives.
///
/// Owns S3 request parsing, identity resolution, and authorization via
/// the [`BucketRegistry`] and [`CredentialRegistry`] traits. Combines
/// a [`Router`] for path-based pre-dispatch with the two-phase
/// resolve/dispatch pipeline.
///
/// # Type Parameters
///
/// - `B`: The runtime's backend for object store creation, signing, and raw HTTP
/// - `R`: The bucket registry for bucket lookup and authorization
/// - `C`: The credential registry for credential and role lookup
/// - `O`: Backend auth for resolving credentials before store/signer creation
pub struct ProxyGateway<B, R, C, O = NoAuth> {
    backend: B,
    bucket_registry: R,
    credential_registry: C,
    backend_auth: O,
    virtual_host_domain: Option<String>,
    credential_resolver: Option<Box<dyn TemporaryCredentialResolver>>,
    router: Router,
    /// When true, error responses include full internal details (for development).
    /// When false, server-side errors use generic messages.
    debug_errors: bool,
}

impl<B, R, C> ProxyGateway<B, R, C>
where
    B: ProxyBackend,
    R: BucketRegistry,
    C: CredentialRegistry,
{
    pub fn new(
        backend: B,
        bucket_registry: R,
        credential_registry: C,
        virtual_host_domain: Option<String>,
    ) -> Self {
        Self {
            backend,
            bucket_registry,
            credential_registry,
            backend_auth: NoAuth,
            virtual_host_domain,
            credential_resolver: None,
            router: Router::new(),
            debug_errors: false,
        }
    }
}

impl<B, R, C, O> ProxyGateway<B, R, C, O>
where
    B: ProxyBackend,
    R: BucketRegistry,
    C: CredentialRegistry,
    O: BackendAuth,
{
    /// Set the backend auth implementation.
    ///
    /// When configured, `dispatch_operation` calls `resolve_credentials`
    /// before accessing the backend — enabling credential resolution
    /// (e.g. OIDC token exchange) for buckets that require it.
    pub fn with_backend_auth<O2: BackendAuth>(self, backend_auth: O2) -> ProxyGateway<B, R, C, O2> {
        ProxyGateway {
            backend: self.backend,
            bucket_registry: self.bucket_registry,
            credential_registry: self.credential_registry,
            backend_auth,
            virtual_host_domain: self.virtual_host_domain,
            credential_resolver: self.credential_resolver,
            router: self.router,
            debug_errors: self.debug_errors,
        }
    }

    /// Set the temporary credential resolver for session token verification.
    ///
    /// When configured, requests with `x-amz-security-token` headers are
    /// resolved via this resolver during identity resolution.
    pub fn with_credential_resolver(
        mut self,
        resolver: impl TemporaryCredentialResolver + 'static,
    ) -> Self {
        self.credential_resolver = Some(Box::new(resolver));
        self
    }

    /// Set the router for path-based request dispatch.
    ///
    /// The router is consulted before the proxy dispatch pipeline.
    /// If a route matches and the handler returns an action, that action
    /// is used directly. Otherwise the request falls through to proxy
    /// dispatch.
    pub fn with_router(mut self, router: Router) -> Self {
        self.router = router;
        self
    }

    /// Enable verbose error messages in S3 error responses.
    ///
    /// When enabled, 500-class errors include the full internal message
    /// (backend errors, config errors, etc.). Disable in production to
    /// avoid leaking infrastructure details to clients.
    pub fn with_debug_errors(mut self, enabled: bool) -> Self {
        self.debug_errors = enabled;
        self
    }

    /// Main entry point: check route handlers, then fall through to proxy dispatch.
    ///
    /// Route handlers are checked in registration order. If none match,
    /// the request is resolved via the normal proxy pipeline.
    ///
    /// Returns a three-variant [`HandlerAction`]. For a simpler two-variant
    /// API, use [`handle_request`](Self::handle_request) instead.
    pub async fn handle(&self, req: &RequestInfo<'_>) -> HandlerAction {
        if let Some(action) = self.router.dispatch(req).await {
            return action;
        }
        self.resolve_request(req.method.clone(), req.path, req.query, req.headers)
            .await
    }

    /// Convenience entry point that resolves `NeedsBody` internally.
    ///
    /// The body is passed through untouched for `Forward` (preserving
    /// zero-copy streaming for GET/PUT). For `NeedsBody` (multipart),
    /// the `collect_body` closure is called to materialize the body.
    ///
    /// Runtimes match on only two variants — `Response` or `Forward`:
    ///
    /// ```rust,ignore
    /// match gateway.handle_request(&req_info, body, |b| to_bytes(b)).await {
    ///     GatewayResponse::Response(result) => build_response(result),
    ///     GatewayResponse::Forward(fwd, body) => forward(fwd, body).await,
    /// }
    /// ```
    pub async fn handle_request<Body, F, Fut, E>(
        &self,
        req: &RequestInfo<'_>,
        body: Body,
        collect_body: F,
    ) -> GatewayResponse<Body>
    where
        F: FnOnce(Body) -> Fut,
        Fut: std::future::Future<Output = Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        match self.handle(req).await {
            HandlerAction::Response(r) => GatewayResponse::Response(r),
            HandlerAction::Forward(f) => GatewayResponse::Forward(f, body),
            HandlerAction::NeedsBody(pending) => match collect_body(body).await {
                Ok(bytes) => GatewayResponse::Response(self.handle_with_body(pending, bytes).await),
                Err(e) => {
                    tracing::error!(error = %e, "failed to read request body");
                    GatewayResponse::Response(error_response(
                        &ProxyError::Internal("failed to read request body".into()),
                        "",
                        "",
                        self.debug_errors,
                    ))
                }
            },
        }
    }

    /// Phase 1: Resolve an incoming request into an action.
    ///
    /// Parses the S3 operation from the request, resolves the caller's
    /// identity, authorizes via the bucket registry, and determines what
    /// the runtime should do next.
    pub async fn resolve_request(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> HandlerAction {
        let request_id = Uuid::new_v4().to_string();

        tracing::info!(
            request_id = %request_id,
            method = %method,
            path = %path,
            query = ?query,
            "incoming request"
        );

        match self
            .resolve_inner(method, path, query, headers, &request_id)
            .await
        {
            Ok(action) => {
                match &action {
                    HandlerAction::Response(resp) => {
                        tracing::info!(
                            request_id = %request_id,
                            status = resp.status,
                            "request completed"
                        );
                    }
                    HandlerAction::Forward(fwd) => {
                        tracing::info!(
                            request_id = %request_id,
                            method = %fwd.method,
                            "forwarding via presigned URL"
                        );
                    }
                    HandlerAction::NeedsBody(_) => {
                        tracing::debug!(
                            request_id = %request_id,
                            "request needs body (multipart)"
                        );
                    }
                }
                action
            }
            Err(err) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %err,
                    status = err.status_code(),
                    s3_code = %err.s3_error_code(),
                    "request failed"
                );
                HandlerAction::Response(error_response(&err, path, &request_id, self.debug_errors))
            }
        }
    }

    /// Phase 2: Complete a multipart operation with the request body.
    ///
    /// Called by the runtime after materializing the body for a `NeedsBody` action.
    pub async fn handle_with_body(&self, pending: PendingRequest, body: Bytes) -> ProxyResult {
        match self.execute_multipart(&pending, body).await {
            Ok(result) => {
                tracing::info!(
                    request_id = %pending.request_id,
                    status = result.status,
                    "multipart request completed"
                );
                result
            }
            Err(err) => {
                tracing::warn!(
                    request_id = %pending.request_id,
                    error = %err,
                    status = err.status_code(),
                    s3_code = %err.s3_error_code(),
                    "multipart request failed"
                );
                error_response(
                    &err,
                    pending.operation.key(),
                    &pending.request_id,
                    self.debug_errors,
                )
            }
        }
    }

    async fn resolve_inner(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        request_id: &str,
    ) -> Result<HandlerAction, ProxyError> {
        // Determine host style
        let host_style = determine_host_style(headers, self.virtual_host_domain.as_deref());

        // Parse the S3 operation
        let operation = request::parse_s3_request(&method, path, query, headers, host_style)?;
        tracing::debug!(operation = ?operation, "parsed S3 operation");

        // Resolve identity
        let identity = auth::resolve_identity(
            &method,
            path,
            query.unwrap_or(""),
            headers,
            &self.credential_registry,
            self.credential_resolver.as_deref(),
        )
        .await?;
        tracing::debug!(identity = ?identity, "resolved identity");

        // Handle ListBuckets — returns virtual bucket list from registry, no backend call
        if matches!(operation, S3Operation::ListBuckets) {
            let buckets = self.bucket_registry.list_buckets(&identity).await?;
            tracing::info!(count = buckets.len(), "listing virtual buckets");
            let xml = ListAllMyBucketsResult {
                owner: self.bucket_registry.bucket_owner(),
                buckets: BucketList { buckets },
            }
            .to_xml();

            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("content-type", "application/xml".parse().unwrap());
            return Ok(HandlerAction::Response(ProxyResult {
                status: 200,
                headers: resp_headers,
                body: ProxyResponseBody::from_bytes(Bytes::from(xml)),
            }));
        }

        // Get bucket name and resolve via registry (includes authorization)
        let bucket_name = operation
            .bucket()
            .ok_or_else(|| ProxyError::InvalidRequest("no bucket in request".into()))?;

        let resolved = self
            .bucket_registry
            .get_bucket(bucket_name, &identity, &operation)
            .await?;

        tracing::debug!(
            bucket = %bucket_name,
            backend_type = %resolved.config.backend_type,
            "resolved bucket config"
        );
        tracing::trace!("authorization passed");

        self.dispatch_operation(
            &method,
            &operation,
            &resolved.config,
            headers,
            resolved.list_rewrite.as_ref(),
            request_id,
        )
        .await
    }

    async fn dispatch_operation(
        &self,
        method: &Method,
        operation: &S3Operation,
        bucket_config: &BucketConfig,
        original_headers: &HeaderMap,
        list_rewrite: Option<&ListRewrite>,
        request_id: &str,
    ) -> Result<HandlerAction, ProxyError> {
        // Resolve backend credentials if needed (e.g. OIDC token exchange).
        // Returns None for buckets with static credentials (zero-copy path),
        // Some(options) with replacement backend_options for dynamic credentials.
        let resolved_config;
        let bucket_config = match self.backend_auth.resolve_credentials(bucket_config).await? {
            Some(options) => {
                resolved_config = BucketConfig {
                    backend_options: options,
                    ..bucket_config.clone()
                };
                &resolved_config
            }
            None => bucket_config,
        };

        match operation {
            S3Operation::GetObject { key, .. } => {
                let fwd = self
                    .build_forward(
                        Method::GET,
                        bucket_config,
                        key,
                        original_headers,
                        &[
                            "range",
                            "if-match",
                            "if-none-match",
                            "if-modified-since",
                            "if-unmodified-since",
                        ],
                    )
                    .await?;
                tracing::debug!(path = fwd.url.path(), "GET via presigned URL");
                Ok(HandlerAction::Forward(fwd))
            }
            S3Operation::HeadObject { key, .. } => {
                let fwd = self
                    .build_forward(
                        Method::HEAD,
                        bucket_config,
                        key,
                        original_headers,
                        &[
                            "range",
                            "if-match",
                            "if-none-match",
                            "if-modified-since",
                            "if-unmodified-since",
                        ],
                    )
                    .await?;
                tracing::debug!(path = fwd.url.path(), "HEAD via presigned URL");
                Ok(HandlerAction::Forward(fwd))
            }
            S3Operation::PutObject { key, .. } => {
                let fwd = self
                    .build_forward(
                        Method::PUT,
                        bucket_config,
                        key,
                        original_headers,
                        &["content-type", "content-length", "content-md5"],
                    )
                    .await?;
                tracing::debug!(path = fwd.url.path(), "PUT via presigned URL");
                Ok(HandlerAction::Forward(fwd))
            }
            S3Operation::DeleteObject { key, .. } => {
                let fwd = self
                    .build_forward(Method::DELETE, bucket_config, key, original_headers, &[])
                    .await?;
                tracing::debug!(path = fwd.url.path(), "DELETE via presigned URL");
                Ok(HandlerAction::Forward(fwd))
            }
            S3Operation::ListBucket { raw_query, .. } => {
                let result = self
                    .handle_list(bucket_config, raw_query.as_deref(), list_rewrite)
                    .await?;
                Ok(HandlerAction::Response(result))
            }
            // Multipart operations need the request body
            S3Operation::CreateMultipartUpload { .. }
            | S3Operation::UploadPart { .. }
            | S3Operation::CompleteMultipartUpload { .. }
            | S3Operation::AbortMultipartUpload { .. } => {
                if !bucket_config.supports_s3_multipart() {
                    return Err(ProxyError::InvalidRequest(format!(
                        "multipart operations not supported for '{}' backends",
                        bucket_config.backend_type
                    )));
                }
                Ok(HandlerAction::NeedsBody(PendingRequest {
                    method: method.clone(),
                    operation: operation.clone(),
                    bucket_config: bucket_config.clone(),
                    original_headers: original_headers.clone(),
                    request_id: request_id.to_string(),
                }))
            }
            _ => Err(ProxyError::Internal("unexpected operation".into())),
        }
    }

    /// Build a [`ForwardRequest`] with a presigned URL for the given operation.
    async fn build_forward(
        &self,
        method: Method,
        config: &BucketConfig,
        key: &str,
        original_headers: &HeaderMap,
        forward_header_names: &[&'static str],
    ) -> Result<ForwardRequest, ProxyError> {
        let signer = self.backend.create_signer(config)?;
        let path = build_object_path(config, key);

        let url = signer
            .signed_url(method.clone(), &path, PRESIGNED_URL_TTL)
            .await
            .map_err(ProxyError::from_object_store_error)?;

        let mut fwd_headers = HeaderMap::new();
        for name in forward_header_names {
            if let Some(v) = original_headers.get(*name) {
                fwd_headers.insert(*name, v.clone());
            }
        }

        Ok(ForwardRequest {
            method,
            url,
            headers: fwd_headers,
        })
    }

    /// LIST via object_store's `PaginatedListStore`.
    ///
    /// Pagination is pushed to the backend — only one page of results is fetched
    /// per request, avoiding loading all objects into memory.
    async fn handle_list(
        &self,
        config: &BucketConfig,
        raw_query: Option<&str>,
        list_rewrite: Option<&ListRewrite>,
    ) -> Result<ProxyResult, ProxyError> {
        let store = self.backend.create_paginated_store(config)?;

        // Parse all query parameters in a single pass
        let list_params = parse_list_query_params(raw_query);
        let client_prefix = &list_params.prefix;
        let delimiter = &list_params.delimiter;

        // Build the full prefix including backend_prefix
        let full_prefix = build_list_prefix(config, client_prefix);

        // Map start-after to raw key space by prepending backend_prefix
        let offset = list_params
            .start_after
            .as_ref()
            .map(|sa| build_list_prefix(config, sa));

        tracing::debug!(
            full_prefix = %full_prefix,
            delimiter = %delimiter,
            max_keys = list_params.max_keys,
            has_page_token = list_params.continuation_token.is_some(),
            "LIST via PaginatedListStore"
        );

        let prefix = if full_prefix.is_empty() {
            None
        } else {
            Some(full_prefix.as_str())
        };

        let opts = PaginatedListOptions {
            offset,
            delimiter: Some(Cow::Owned(delimiter.clone())),
            max_keys: Some(list_params.max_keys),
            page_token: list_params.continuation_token.clone(),
            ..Default::default()
        };

        let paginated = store
            .list_paginated(prefix, opts)
            .await
            .map_err(ProxyError::from_object_store_error)?;

        // Build S3 XML response from paginated result
        let key_count = paginated.result.objects.len() + paginated.result.common_prefixes.len();
        let xml = build_list_xml(
            &ListXmlParams {
                bucket_name: &config.name,
                client_prefix,
                delimiter,
                max_keys: list_params.max_keys,
                is_truncated: paginated.page_token.is_some(),
                key_count,
                start_after: &list_params.start_after,
                continuation_token: &list_params.continuation_token,
                next_continuation_token: paginated.page_token,
            },
            &paginated.result,
            config,
            list_rewrite,
        )?;

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("content-type", "application/xml".parse().unwrap());

        Ok(ProxyResult {
            status: 200,
            headers: resp_headers,
            body: ProxyResponseBody::Bytes(Bytes::from(xml)),
        })
    }

    /// Execute a multipart operation via raw signed HTTP.
    async fn execute_multipart(
        &self,
        pending: &PendingRequest,
        body: Bytes,
    ) -> Result<ProxyResult, ProxyError> {
        let backend_url = build_backend_url(&pending.bucket_config, &pending.operation)?;

        tracing::debug!(backend_url = %backend_url, "multipart via raw HTTP");

        let mut headers = HeaderMap::new();

        // Forward relevant headers
        for header_name in &["content-type", "content-length", "content-md5"] {
            if let Some(val) = pending.original_headers.get(*header_name) {
                headers.insert(*header_name, val.clone());
            }
        }

        let payload_hash = if body.is_empty() {
            UNSIGNED_PAYLOAD.to_string()
        } else {
            hash_payload(&body)
        };

        sign_s3_request(
            &pending.method,
            &backend_url,
            &mut headers,
            &pending.bucket_config,
            &payload_hash,
        )?;

        let raw_resp = self
            .backend
            .send_raw(pending.method.clone(), backend_url, headers, body)
            .await?;

        tracing::debug!(status = raw_resp.status, "multipart backend response");

        Ok(ProxyResult {
            status: raw_resp.status,
            headers: raw_resp.headers,
            body: ProxyResponseBody::from_bytes(raw_resp.body),
        })
    }
}

fn determine_host_style(headers: &HeaderMap, virtual_host_domain: Option<&str>) -> HostStyle {
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

fn error_response(err: &ProxyError, resource: &str, request_id: &str, debug: bool) -> ProxyResult {
    let xml = ErrorResponse::from_proxy_error(err, resource, request_id, debug).to_xml();
    let body = ProxyResponseBody::from_bytes(Bytes::from(xml));
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/xml".parse().unwrap());

    ProxyResult {
        status: err.status_code(),
        headers,
        body,
    }
}

/// Build an object_store Path from a bucket config and client-visible key.
fn build_object_path(config: &BucketConfig, key: &str) -> object_store::path::Path {
    match &config.backend_prefix {
        Some(prefix) => {
            let p = prefix.trim_end_matches('/');
            if p.is_empty() {
                object_store::path::Path::from(key)
            } else {
                let mut full_key = String::with_capacity(p.len() + 1 + key.len());
                full_key.push_str(p);
                full_key.push('/');
                full_key.push_str(key);
                object_store::path::Path::from(full_key)
            }
        }
        None => object_store::path::Path::from(key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::response::BucketEntry;
    use crate::backend::RawResponse;
    use crate::registry::{BucketRegistry, CredentialRegistry, ResolvedBucket};
    use crate::types::{ResolvedIdentity, RoleConfig, StoredCredential};
    use object_store::list::PaginatedListStore;
    use object_store::signer::Signer;
    use std::collections::HashMap;
    use std::sync::Arc;

    // ── Mocks ───────────────────────────────────────────────────────

    #[derive(Clone)]
    struct MockBackend;

    impl ProxyBackend for MockBackend {
        fn create_paginated_store(
            &self,
            _config: &BucketConfig,
        ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
            unimplemented!("not needed for forward tests")
        }

        fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError> {
            // Build a real S3 signer from the test config — produces a valid presigned URL.
            crate::backend::build_signer(config)
        }

        async fn send_raw(
            &self,
            _method: http::Method,
            _url: String,
            _headers: HeaderMap,
            _body: Bytes,
        ) -> Result<RawResponse, ProxyError> {
            unimplemented!("not needed for forward tests")
        }
    }

    #[derive(Clone)]
    struct MockRegistry;

    impl BucketRegistry for MockRegistry {
        async fn get_bucket(
            &self,
            name: &str,
            _identity: &ResolvedIdentity,
            _operation: &S3Operation,
        ) -> Result<ResolvedBucket, ProxyError> {
            Ok(ResolvedBucket {
                config: test_bucket_config(name),
                list_rewrite: None,
            })
        }

        async fn list_buckets(
            &self,
            _identity: &ResolvedIdentity,
        ) -> Result<Vec<BucketEntry>, ProxyError> {
            Ok(vec![])
        }
    }

    #[derive(Clone)]
    struct MockCreds;

    impl CredentialRegistry for MockCreds {
        async fn get_credential(
            &self,
            _access_key_id: &str,
        ) -> Result<Option<StoredCredential>, ProxyError> {
            Ok(None)
        }

        async fn get_role(&self, _role_id: &str) -> Result<Option<RoleConfig>, ProxyError> {
            Ok(None)
        }
    }

    fn test_bucket_config(name: &str) -> BucketConfig {
        let mut backend_options = HashMap::new();
        backend_options.insert(
            "endpoint".into(),
            "https://s3.us-east-1.amazonaws.com".into(),
        );
        backend_options.insert("bucket_name".into(), "backend-bucket".into());
        backend_options.insert("region".into(), "us-east-1".into());
        backend_options.insert("access_key_id".into(), "AKIAIOSFODNN7EXAMPLE".into());
        backend_options.insert(
            "secret_access_key".into(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        );
        BucketConfig {
            name: name.to_string(),
            backend_type: "s3".into(),
            backend_prefix: None,
            anonymous_access: true,
            allowed_roles: vec![],
            backend_options,
        }
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    fn gateway() -> ProxyGateway<MockBackend, MockRegistry, MockCreds> {
        ProxyGateway::new(MockBackend, MockRegistry, MockCreds, None)
    }

    // ── Tests ───────────────────────────────────────────────────────

    #[test]
    fn get_forward_preserves_range_header() {
        run(async {
            let gw = gateway();
            let mut headers = HeaderMap::new();
            headers.insert("range", "bytes=0-99".parse().unwrap());
            let action = gw
                .resolve_request(Method::GET, "/test-bucket/key.txt", None, &headers)
                .await;

            match action {
                HandlerAction::Forward(fwd) => {
                    assert_eq!(fwd.method, Method::GET);
                    assert_eq!(
                        fwd.headers.get("range").map(|v| v.to_str().unwrap()),
                        Some("bytes=0-99"),
                        "GET forward should pass through the Range header"
                    );
                }
                other => panic!("expected Forward, got {:?}", std::mem::discriminant(&other)),
            }
        });
    }

    #[test]
    fn head_forward_preserves_range_header() {
        run(async {
            let gw = gateway();
            let mut headers = HeaderMap::new();
            headers.insert("range", "bytes=0-1023".parse().unwrap());
            let action = gw
                .resolve_request(Method::HEAD, "/test-bucket/key.txt", None, &headers)
                .await;

            match action {
                HandlerAction::Forward(fwd) => {
                    assert_eq!(fwd.method, Method::HEAD);
                    assert_eq!(
                        fwd.headers.get("range").map(|v| v.to_str().unwrap()),
                        Some("bytes=0-1023"),
                        "HEAD forward should pass through the Range header"
                    );
                }
                other => panic!("expected Forward, got {:?}", std::mem::discriminant(&other)),
            }
        });
    }
}
