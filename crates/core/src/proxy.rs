//! The main proxy gateway that ties together registry lookup and backend forwarding.
//!
//! [`ProxyGateway`] is generic over the runtime's backend, bucket registry,
//! and credential registry.
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
//! For lower-level control, use [`ProxyGateway::resolve_request`] which returns the
//! three-variant [`HandlerAction`] directly.

use crate::api::list::{
    build_list_prefix, build_list_xml, build_list_xml_v1, parse_list_query_params, ListXmlParams,
    ListXmlParamsV1,
};
use crate::api::list_rewrite::ListRewrite;
use crate::api::request::{self, HostStyle};
use crate::api::response::{BucketList, ErrorResponse, ListAllMyBucketsResult};
use crate::auth;
use crate::auth::TemporaryCredentialResolver;
use crate::backend::multipart::{build_backend_url, sign_s3_request};
use crate::backend::request_signer::{hash_payload, UNSIGNED_PAYLOAD};
use crate::backend::ForwardResponse;
use crate::backend::ProxyBackend;
use crate::error::ProxyError;
use crate::maybe_send::MaybeSend;
use crate::middleware::{
    CompletedRequest, Dispatch, DispatchContext, DispatchFuture, ErasedMiddleware, Middleware, Next,
};
use crate::registry::{BucketRegistry, CredentialRegistry};
use crate::route_handler::{ProxyResponseBody, RequestInfo};
use crate::router::Router;
use crate::types::{BucketConfig, ResolvedIdentity, S3Operation};
use bytes::Bytes;
use http::{HeaderMap, Method};
use object_store::list::PaginatedListOptions;
use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;
use uuid::Uuid;

/// TTL for presigned URLs. Short because they're used immediately.
const PRESIGNED_URL_TTL: Duration = Duration::from_secs(300);

// Re-export types that were historically defined here for backwards compatibility.
pub use crate::route_handler::{
    filter_response_headers, ForwardRequest, HandlerAction, PendingRequest, ProxyResult,
    RESPONSE_HEADER_DENYLIST,
};

/// Simplified two-variant result from [`ProxyGateway::handle_request`].
///
/// The response body type `S` is the `ProxyBackend`'s `ResponseBody` — opaque
/// to the core, passed through to the runtime for client delivery.
pub enum GatewayResponse<S> {
    /// A fully formed response ready to send to the client.
    Response(ProxyResult),
    /// A forwarded response from the backend, with the runtime's native
    /// body type for streaming.
    Forward(ForwardResponse<S>),
}

/// Metadata from request resolution, used for post-dispatch callbacks.
pub struct RequestMetadata {
    /// The unique request identifier.
    pub request_id: String,
    /// The resolved caller identity, if any.
    pub identity: Option<ResolvedIdentity>,
    /// The parsed S3 operation, if determined.
    pub operation: Option<S3Operation>,
    /// The target bucket name, if the operation targets a specific bucket.
    pub bucket: Option<String>,
    /// The IP address of the client, used for anonymous user identification.
    pub source_ip: Option<IpAddr>,
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
/// - `B`: The runtime's backend for object store creation, signing, forwarding, and raw HTTP
/// - `R`: The bucket registry for bucket lookup and authorization
/// - `C`: The credential registry for credential and role lookup
pub struct ProxyGateway<B, R, C> {
    backend: B,
    bucket_registry: R,
    credential_registry: C,
    middleware: Vec<Box<dyn ErasedMiddleware>>,
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
    /// Create a new proxy gateway.
    ///
    /// - `backend`: the runtime-specific backend for signing, forwarding, and raw HTTP
    /// - `bucket_registry`: resolves virtual bucket names to backend configs and authorizes access
    /// - `credential_registry`: looks up long-lived credentials and IAM roles
    /// - `virtual_host_domain`: when set, enables virtual-hosted-style bucket addressing
    ///   (e.g. `bucket.example.com`)
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
            middleware: Vec::new(),
            virtual_host_domain,
            credential_resolver: None,
            router: Router::new(),
            debug_errors: false,
        }
    }

    /// Add a middleware to the dispatch chain.
    ///
    /// Middleware runs after identity resolution and authorization, wrapping
    /// the backend dispatch call. Middleware executes in registration order.
    pub fn with_middleware(mut self, middleware: impl Middleware) -> Self {
        self.middleware.push(Box::new(middleware));
        self
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

    /// Convenience entry point that resolves `NeedsBody` internally and
    /// executes forwarding via the [`ProxyBackend`].
    ///
    /// Route handler matches bypass the forwarding/after_dispatch path for
    /// simplicity. For the proxy pipeline, `after_dispatch` is fired on all
    /// middleware after the response is determined.
    ///
    /// Runtimes match on only two variants — `Response` or `Forward`:
    ///
    /// ```rust,ignore
    /// match gateway.handle_request(&req_info, body, |b| to_bytes(b)).await {
    ///     GatewayResponse::Response(result) => build_response(result),
    ///     GatewayResponse::Forward(resp) => stream_response(resp),
    /// }
    /// ```
    pub async fn handle_request<Body, CF, Fut, E>(
        &self,
        req: &RequestInfo<'_>,
        body: Body,
        collect_body: CF,
    ) -> GatewayResponse<B::ResponseBody>
    where
        Body: MaybeSend + 'static,
        CF: FnOnce(Body) -> Fut,
        Fut: std::future::Future<Output = Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        // Route handlers first (bypass forwarder/after_dispatch for simplicity)
        if let Some(action) = self.router.dispatch(req).await {
            return match action {
                HandlerAction::Response(r) => GatewayResponse::Response(r),
                HandlerAction::Forward(fwd) => match self.backend.forward(fwd, body).await {
                    Ok(mut resp) => {
                        resp.headers = filter_response_headers(&resp.headers);
                        GatewayResponse::Forward(resp)
                    }
                    Err(e) => GatewayResponse::Response(error_response(
                        &e,
                        req.path,
                        "",
                        self.debug_errors,
                    )),
                },
                HandlerAction::NeedsBody(_) => GatewayResponse::Response(error_response(
                    &ProxyError::Internal("unexpected NeedsBody from route handler".into()),
                    req.path,
                    "",
                    self.debug_errors,
                )),
            };
        }

        // Resolve via proxy pipeline (with metadata for after_dispatch)
        let (action, metadata) = self.resolve_request_with_metadata(req).await;

        // Helper to extract response body size
        fn response_body_bytes(body: &ProxyResponseBody) -> Option<u64> {
            match body {
                ProxyResponseBody::Bytes(b) => Some(b.len() as u64),
                ProxyResponseBody::Empty => Some(0),
            }
        }

        fn content_length_from_headers(headers: &HeaderMap) -> Option<u64> {
            headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
        }

        let request_bytes = content_length_from_headers(req.headers);

        let (response, status, resp_bytes, was_forwarded) = match action {
            HandlerAction::Response(r) => {
                let s = r.status;
                let rb = response_body_bytes(&r.body);
                (GatewayResponse::Response(r), s, rb, false)
            }
            HandlerAction::Forward(fwd) => match self.backend.forward(fwd, body).await {
                Ok(mut resp) => {
                    resp.headers = filter_response_headers(&resp.headers);
                    let s = resp.status;
                    let cl = resp.content_length;
                    (GatewayResponse::Forward(resp), s, cl, true)
                }
                Err(e) => {
                    let err_resp =
                        error_response(&e, req.path, &metadata.request_id, self.debug_errors);
                    let s = err_resp.status;
                    (GatewayResponse::Response(err_resp), s, None, true)
                }
            },
            HandlerAction::NeedsBody(pending) => match collect_body(body).await {
                Ok(bytes) => {
                    let result = self.handle_with_body(pending, bytes).await;
                    let s = result.status;
                    let rb = response_body_bytes(&result.body);
                    (GatewayResponse::Response(result), s, rb, false)
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to read request body");
                    let err_resp = error_response(
                        &ProxyError::Internal("failed to read request body".into()),
                        "",
                        &metadata.request_id,
                        self.debug_errors,
                    );
                    let s = err_resp.status;
                    (GatewayResponse::Response(err_resp), s, None, false)
                }
            },
        };

        // Fire after_dispatch on all middleware
        let completed = CompletedRequest {
            request_id: &metadata.request_id,
            identity: metadata.identity.as_ref(),
            operation: metadata.operation.as_ref(),
            bucket: metadata.bucket.as_deref(),
            status,
            response_bytes: resp_bytes,
            request_bytes,
            was_forwarded,
            source_ip: metadata.source_ip,
        };
        for m in &self.middleware {
            m.after_dispatch(&completed).await;
        }

        response
    }

    /// Resolve an incoming request into an action.
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
        source_ip: Option<IpAddr>,
    ) -> HandlerAction {
        let req = RequestInfo::new(&method, path, query, headers, source_ip);
        let (action, _metadata) = self.resolve_request_with_metadata(&req).await;
        action
    }

    /// Like [`resolve_request`](Self::resolve_request), but also returns
    /// [`RequestMetadata`] for post-dispatch callbacks (e.g. metering).
    pub(crate) async fn resolve_request_with_metadata(
        &self,
        req: &RequestInfo<'_>,
    ) -> (HandlerAction, RequestMetadata) {
        let request_id = Uuid::new_v4().to_string();

        tracing::info!(
            request_id = %request_id,
            method = %req.method,
            path = %req.path,
            query = ?req.query,
            "incoming request"
        );

        // Determine host style
        let host_style = determine_host_style(req.headers, self.virtual_host_domain.as_deref());

        // Parse the S3 operation
        let operation =
            match request::parse_s3_request(req.method, req.path, req.query, req.headers, host_style) {
                Ok(op) => op,
                Err(err) => return self.error_result(err, req.path, &request_id, req.source_ip),
            };
        tracing::debug!(operation = ?operation, "parsed S3 operation");

        // Resolve identity — use the original client-facing path and query for
        // signature verification when provided (e.g. path-mapping rewrites).
        let identity = match auth::resolve_identity(
            req.method,
            req.signing_path.unwrap_or(req.path),
            req.signing_query.or(req.query).unwrap_or(""),
            req.headers,
            &self.credential_registry,
            self.credential_resolver.as_deref(),
        )
        .await
        {
            Ok(id) => id,
            Err(err) => return self.error_result(err, req.path, &request_id, req.source_ip),
        };
        tracing::debug!(identity = ?identity, "resolved identity");

        // Resolve bucket config (if the operation targets a specific bucket).
        let resolved = if let Some(bucket_name) = operation.bucket() {
            match self
                .bucket_registry
                .get_bucket(bucket_name, &identity, &operation)
                .await
            {
                Ok(resolved) => {
                    tracing::debug!(
                        bucket = %bucket_name,
                        backend_type = %resolved.config.backend_type,
                        "resolved bucket config"
                    );
                    tracing::trace!("authorization passed");
                    Some(resolved)
                }
                Err(err) => return self.error_result(err, req.path, &request_id, req.source_ip),
            }
        } else {
            None
        };

        // Build middleware context
        let ctx = DispatchContext {
            identity: &identity,
            operation: &operation,
            bucket_config: resolved.as_ref().map(|r| Cow::Borrowed(&r.config)),
            headers: req.headers,
            source_ip: req.source_ip,
            request_id: &request_id,
            list_rewrite: resolved.as_ref().and_then(|r| r.list_rewrite.as_ref()),
            display_name: resolved.as_ref().and_then(|r| r.display_name.as_deref()),
            extensions: http::Extensions::new(),
        };

        let next = Next::new(&self.middleware, self);
        let metadata = RequestMetadata {
            request_id: request_id.clone(),
            identity: Some(identity.clone()),
            operation: Some(operation.clone()),
            bucket: operation.bucket().map(str::to_string),
            source_ip: req.source_ip,
        };

        match next.run(ctx).await {
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
                (action, metadata)
            }
            Err(err) => self.error_result(err, req.path, &request_id, req.source_ip),
        }
    }

    /// Build an error action + metadata pair for early returns.
    fn error_result(
        &self,
        err: ProxyError,
        path: &str,
        request_id: &str,
        source_ip: Option<IpAddr>,
    ) -> (HandlerAction, RequestMetadata) {
        tracing::warn!(
            request_id = %request_id,
            error = %err,
            status = err.status_code(),
            s3_code = %err.s3_error_code(),
            "request failed"
        );
        let metadata = RequestMetadata {
            request_id: request_id.to_string(),
            identity: None,
            operation: None,
            bucket: None,
            source_ip,
        };
        (
            HandlerAction::Response(error_response(&err, path, request_id, self.debug_errors)),
            metadata,
        )
    }

    /// Phase 2: Complete a multipart operation with the request body.
    ///
    /// Called by the runtime after materializing the body for a `NeedsBody` action.
    /// Middleware is not re-run here — it already executed during phase 1
    /// when the `NeedsBody` action was produced.
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

    async fn dispatch_operation(
        &self,
        ctx: &DispatchContext<'_>,
    ) -> Result<HandlerAction, ProxyError> {
        let original_headers = ctx.headers;
        let list_rewrite = ctx.list_rewrite;
        let request_id = ctx.request_id;
        let operation = ctx.operation;

        // ListBuckets has no bucket config — handle it first.
        if matches!(operation, S3Operation::ListBuckets) {
            let buckets = self.bucket_registry.list_buckets(ctx.identity).await?;
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

        // All remaining operations require a bucket config.
        let bucket_config = ctx
            .bucket_config
            .as_deref()
            .expect("bucket_config must be set for bucket-targeted operations");

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
                        request_id,
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
                        request_id,
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
                        request_id,
                    )
                    .await?;
                tracing::debug!(path = fwd.url.path(), "PUT via presigned URL");
                Ok(HandlerAction::Forward(fwd))
            }
            S3Operation::DeleteObject { key, .. } => {
                let fwd = self
                    .build_forward(
                        Method::DELETE,
                        bucket_config,
                        key,
                        original_headers,
                        &[],
                        request_id,
                    )
                    .await?;
                tracing::debug!(path = fwd.url.path(), "DELETE via presigned URL");
                Ok(HandlerAction::Forward(fwd))
            }
            S3Operation::ListBucket { raw_query, .. } => {
                let result = self
                    .handle_list(
                        bucket_config,
                        raw_query.as_deref(),
                        list_rewrite,
                        ctx.display_name,
                    )
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
        request_id: &str,
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
            request_id: request_id.to_string(),
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
        display_name: Option<&str>,
    ) -> Result<ProxyResult, ProxyError> {
        let store = self.backend.create_paginated_store(config)?;

        // Parse all query parameters in a single pass
        let list_params = parse_list_query_params(raw_query);
        let client_prefix = &list_params.prefix;
        let delimiter = &list_params.delimiter;

        // Build the full prefix including backend_prefix
        let full_prefix = build_list_prefix(config, client_prefix);

        // Map start-after (V2) or marker (V1) to raw key space by prepending backend_prefix
        let offset = if list_params.is_v2 {
            list_params
                .start_after
                .as_ref()
                .map(|sa| build_list_prefix(config, sa))
        } else {
            list_params
                .marker
                .as_ref()
                .map(|m| build_list_prefix(config, m))
        };

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
            delimiter: if delimiter.is_empty() {
                None
            } else {
                Some(Cow::Owned(delimiter.clone()))
            },
            max_keys: Some(list_params.max_keys),
            page_token: list_params.continuation_token.clone(),
            ..Default::default()
        };

        let paginated = store
            .list_paginated(prefix, opts)
            .await
            .map_err(ProxyError::from_object_store_error)?;

        // Build S3 XML response from paginated result
        let bucket_name = display_name.unwrap_or(&config.name);
        let is_truncated = paginated.page_token.is_some();

        let xml = if list_params.is_v2 {
            let key_count = paginated.result.objects.len() + paginated.result.common_prefixes.len();
            build_list_xml(
                &ListXmlParams {
                    bucket_name,
                    client_prefix,
                    delimiter,
                    max_keys: list_params.max_keys,
                    is_truncated,
                    key_count,
                    start_after: &list_params.start_after,
                    continuation_token: &list_params.continuation_token,
                    next_continuation_token: paginated.page_token,
                    encoding_type: &list_params.encoding_type,
                },
                &paginated.result,
                config,
                list_rewrite,
            )?
        } else {
            // Derive NextMarker from the last returned key when truncated
            let next_marker = if is_truncated {
                paginated
                    .result
                    .objects
                    .last()
                    .map(|obj| obj.location.to_string())
            } else {
                None
            };
            build_list_xml_v1(
                &ListXmlParamsV1 {
                    bucket_name,
                    client_prefix,
                    delimiter,
                    max_keys: list_params.max_keys,
                    is_truncated,
                    marker: list_params.marker.as_deref().unwrap_or(""),
                    next_marker,
                    encoding_type: &list_params.encoding_type,
                },
                &paginated.result,
                config,
                list_rewrite,
            )?
        };

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

        let method = pending.operation.method();

        sign_s3_request(
            &method,
            &backend_url,
            &mut headers,
            &pending.bucket_config,
            &payload_hash,
        )?;

        let raw_resp = self
            .backend
            .send_raw(method, backend_url, headers, body)
            .await?;

        tracing::debug!(status = raw_resp.status, "multipart backend response");

        Ok(ProxyResult {
            status: raw_resp.status,
            headers: filter_response_headers(&raw_resp.headers),
            body: ProxyResponseBody::from_bytes(raw_resp.body),
        })
    }
}

impl<B, R, C> Dispatch for ProxyGateway<B, R, C>
where
    B: ProxyBackend,
    R: BucketRegistry,
    C: CredentialRegistry,
{
    fn dispatch<'a>(&'a self, ctx: DispatchContext<'a>) -> DispatchFuture<'a> {
        Box::pin(async move { self.dispatch_operation(&ctx).await })
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
        type ResponseBody = ();

        async fn forward<Body: MaybeSend + 'static>(
            &self,
            _request: ForwardRequest,
            _body: Body,
        ) -> Result<ForwardResponse<()>, ProxyError> {
            unimplemented!("not needed for resolve_request tests")
        }

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
                display_name: None,
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
                .resolve_request(Method::GET, "/test-bucket/key.txt", None, &headers, None)
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
                .resolve_request(Method::HEAD, "/test-bucket/key.txt", None, &headers, None)
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

    // -- Middleware test types -----------------------------------------------

    struct BlockMiddleware;

    impl crate::middleware::Middleware for BlockMiddleware {
        async fn handle<'a>(
            &'a self,
            _ctx: crate::middleware::DispatchContext<'a>,
            _next: crate::middleware::Next<'a>,
        ) -> Result<HandlerAction, ProxyError> {
            Ok(HandlerAction::Response(ProxyResult {
                status: 429,
                headers: HeaderMap::new(),
                body: ProxyResponseBody::Empty,
            }))
        }
    }

    struct PassMiddleware;

    impl crate::middleware::Middleware for PassMiddleware {
        async fn handle<'a>(
            &'a self,
            ctx: crate::middleware::DispatchContext<'a>,
            next: crate::middleware::Next<'a>,
        ) -> Result<HandlerAction, ProxyError> {
            next.run(ctx).await
        }
    }

    // -- Middleware integration tests ----------------------------------------

    #[test]
    fn middleware_short_circuits_request() {
        run(async {
            let gw = gateway().with_middleware(BlockMiddleware);
            let headers = HeaderMap::new();
            let action = gw
                .resolve_request(Method::GET, "/test-bucket/key.txt", None, &headers, None)
                .await;

            match action {
                HandlerAction::Response(resp) => {
                    assert_eq!(resp.status, 429, "blocking middleware should return 429");
                }
                other => panic!(
                    "expected Response, got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        });
    }

    #[test]
    fn middleware_passthrough_allows_request() {
        run(async {
            let gw = gateway().with_middleware(PassMiddleware);
            let headers = HeaderMap::new();
            let action = gw
                .resolve_request(Method::GET, "/test-bucket/key.txt", None, &headers, None)
                .await;

            match action {
                HandlerAction::Forward(fwd) => {
                    assert_eq!(
                        fwd.method,
                        Method::GET,
                        "passthrough middleware should allow normal forwarding"
                    );
                }
                other => panic!("expected Forward, got {:?}", std::mem::discriminant(&other)),
            }
        });
    }
}
