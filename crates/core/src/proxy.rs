//! The main proxy gateway that ties together middleware and backend forwarding.
//!
//! [`ProxyGateway`] is generic over the runtime's backend and forwarder.
//! S3 request parsing, identity resolution, and bucket authorization are
//! handled by middleware (see [`crate::s3`]).
//!
//! ## Proxy dispatch (two-phase)
//!
//! The request enters the middleware chain, then the two-phase pipeline:
//!
//! 1. **Middleware chain** -- enriches the request context with S3 operation,
//!    identity, and bucket config, then delegates to the terminal dispatch
//!    function which decides the action:
//!    - GET/HEAD/PUT/DELETE -> [`HandlerAction::Forward`] with a presigned URL
//!    - LIST -> [`HandlerAction::Response`] with XML body
//!    - Multipart -> [`HandlerAction::NeedsBody`] (body required)
//!    - Errors/synthetic -> [`HandlerAction::Response`]
//!
//! 2. **`handle_with_body`** -- completes multipart operations once the body arrives.
//!
//! ## Runtime integration
//!
//! The recommended entry point is [`ProxyGateway::handle_request`], which returns a
//! two-variant [`GatewayResponse<B>`]:
//!
//! - **`Response`** -- a fully formed response to send to the client
//! - **`Forward`** -- a presigned URL plus the original body for zero-copy streaming
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

use crate::api::list::{build_list_prefix, build_list_xml, parse_list_query_params, ListXmlParams};
use crate::api::list_rewrite::ListRewrite;
use crate::api::response::{BucketList, ErrorResponse, ListAllMyBucketsResult};
use crate::auth::TemporaryCredentialResolver;
use crate::backend::multipart::{build_backend_url, sign_s3_request};
use crate::backend::request_signer::{hash_payload, UNSIGNED_PAYLOAD};
use crate::backend::ProxyBackend;
use crate::error::ProxyError;
use crate::forwarder::{ForwardResponse, Forwarder};
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::middleware::{
    CompletedRequest, Dispatch, DispatchFuture, ErasedMiddleware, Middleware, Next, RequestContext,
};
use crate::registry::{BucketRegistry, CredentialRegistry};
use crate::route_handler::{ProxyResponseBody, RequestInfo};
use crate::s3::ResolvedBucketList;
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
/// The response body type `S` is the `Forwarder`'s `ResponseBody` -- opaque
/// to the core, passed through to the runtime for client delivery.
pub enum GatewayResponse<S> {
    /// A fully formed response ready to send to the client.
    Response(ProxyResult),
    /// A forwarded response from the backend, with the runtime's native
    /// body type for streaming.
    Forward(ForwardResponse<S>),
}

/// The core proxy gateway, generic over runtime primitives.
///
/// Runs a composable middleware chain followed by backend dispatch.
/// S3 request parsing, identity resolution, and bucket authorization are
/// handled by middleware registered via [`with_s3_defaults`](Self::with_s3_defaults)
/// or individually via [`with_middleware`](Self::with_middleware).
///
/// # Type Parameters
///
/// - `B`: The runtime's backend for object store creation, signing, and raw HTTP
/// - `F`: The forwarder that executes presigned backend requests
pub struct ProxyGateway<B, F> {
    backend: B,
    forwarder: F,
    middleware: Vec<Box<dyn ErasedMiddleware>>,
    virtual_host_domain: Option<String>,
    /// When true, error responses include full internal details (for development).
    /// When false, server-side errors use generic messages.
    debug_errors: bool,
}

impl<B, F> ProxyGateway<B, F>
where
    B: ProxyBackend,
    F: MaybeSend + MaybeSync,
{
    /// Create a new proxy gateway with the given backend and forwarder.
    ///
    /// No middleware is registered by default. Use [`with_s3_defaults`](Self::with_s3_defaults)
    /// to register the standard S3 middleware stack, or register individual
    /// middleware via [`with_middleware`](Self::with_middleware).
    pub fn new(backend: B, forwarder: F, virtual_host_domain: Option<String>) -> Self {
        Self {
            backend,
            forwarder,
            middleware: Vec::new(),
            virtual_host_domain,
            debug_errors: false,
        }
    }

    /// Register the standard S3 middleware stack.
    ///
    /// Adds [`S3OpParser`](crate::s3::S3OpParser), [`AuthMiddleware`](crate::s3::AuthMiddleware),
    /// and [`BucketResolver`](crate::s3::BucketResolver) in order.
    pub fn with_s3_defaults<R: BucketRegistry, C: CredentialRegistry>(
        self,
        bucket_registry: R,
        credential_registry: C,
    ) -> Self {
        let domain = self.virtual_host_domain.clone();
        self.with_middleware(crate::s3::S3OpParser::new(domain))
            .with_middleware(crate::s3::AuthMiddleware::new(credential_registry))
            .with_middleware(crate::s3::BucketResolver::new(bucket_registry))
    }

    /// Register the standard S3 middleware stack with a credential resolver.
    ///
    /// Like [`with_s3_defaults`](Self::with_s3_defaults), but also configures
    /// session token verification via the given [`TemporaryCredentialResolver`].
    pub fn with_s3_defaults_and_resolver<R: BucketRegistry, C: CredentialRegistry>(
        self,
        bucket_registry: R,
        credential_registry: C,
        credential_resolver: impl TemporaryCredentialResolver + 'static,
    ) -> Self {
        let domain = self.virtual_host_domain.clone();
        self.with_middleware(crate::s3::S3OpParser::new(domain))
            .with_middleware(
                crate::s3::AuthMiddleware::new(credential_registry)
                    .with_credential_resolver(credential_resolver),
            )
            .with_middleware(crate::s3::BucketResolver::new(bucket_registry))
    }

    /// Add a middleware to the dispatch chain.
    ///
    /// Middleware executes in registration order. Use this to add custom
    /// middleware such as rate limiting, routing, or CORS support.
    pub fn with_middleware(mut self, middleware: impl Middleware) -> Self {
        self.middleware.push(Box::new(middleware));
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
    /// executes forwarding via the [`Forwarder`].
    ///
    /// The request flows through the middleware chain (including any
    /// registered [`Router`](crate::router::Router) middleware) before
    /// reaching backend dispatch. `after_dispatch` is fired on all
    /// middleware after the response is determined.
    ///
    /// Runtimes match on only two variants -- `Response` or `Forward`:
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
    ) -> GatewayResponse<F::ResponseBody>
    where
        F: Forwarder<Body>,
        CF: FnOnce(Body) -> Fut,
        Fut: std::future::Future<Output = Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        let request_id = Uuid::new_v4().to_string();

        tracing::info!(
            request_id = %request_id,
            method = %req.method,
            path = %req.path,
            query = ?req.query,
            "incoming request"
        );

        let ctx = RequestContext {
            method: req.method,
            path: req.path,
            query: req.query,
            headers: req.headers,
            source_ip: req.source_ip,
            request_id: request_id.clone(),
            extensions: http::Extensions::new(),
        };

        let next = Next::new(&self.middleware, self);
        let action = match next.run(ctx).await {
            Ok(action) => action,
            Err(err) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %err,
                    status = err.status_code(),
                    s3_code = %err.s3_error_code(),
                    "request failed"
                );
                HandlerAction::Response(error_response(
                    &err,
                    req.path,
                    &request_id,
                    self.debug_errors,
                ))
            }
        };

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
            HandlerAction::Forward(fwd) => {
                let extra_headers = fwd.response_headers.clone();
                match self.forwarder.forward(fwd, body).await {
                    Ok(mut resp) => {
                        for (k, v) in &extra_headers {
                            resp.headers.insert(k, v.clone());
                        }
                        let s = resp.status;
                        let cl = resp.content_length;
                        (GatewayResponse::Forward(resp), s, cl, true)
                    }
                    Err(e) => {
                        let err_resp = error_response(&e, req.path, &request_id, self.debug_errors);
                        let s = err_resp.status;
                        (GatewayResponse::Response(err_resp), s, None, true)
                    }
                }
            }
            HandlerAction::NeedsBody(pending) => match collect_body(body).await {
                Ok(bytes) => {
                    let extra_headers = pending.response_headers.clone();
                    let mut result = self.handle_with_body(pending, bytes).await;
                    for (k, v) in &extra_headers {
                        result.headers.insert(k, v.clone());
                    }
                    let s = result.status;
                    let rb = response_body_bytes(&result.body);
                    (GatewayResponse::Response(result), s, rb, false)
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to read request body");
                    let err_resp = error_response(
                        &ProxyError::Internal("failed to read request body".into()),
                        "",
                        &request_id,
                        self.debug_errors,
                    );
                    let s = err_resp.status;
                    (GatewayResponse::Response(err_resp), s, None, false)
                }
            },
        };

        // Fire after_dispatch on all middleware.
        // Identity/operation/bucket are not available here since the middleware
        // chain consumed the context. Middleware that needs this data for
        // after_dispatch (e.g. metering) captures it during handle().
        let completed = CompletedRequest {
            request_id: &request_id,
            identity: None,
            operation: None,
            bucket: None,
            status,
            response_bytes: resp_bytes,
            request_bytes,
            was_forwarded,
            source_ip: req.source_ip,
        };
        for m in &self.middleware {
            m.after_dispatch(&completed).await;
        }

        response
    }

    /// Phase 2: Complete a multipart operation with the request body.
    ///
    /// Called by the runtime after materializing the body for a `NeedsBody` action.
    /// Middleware is not re-run here -- it already executed during phase 1
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
        ctx: &RequestContext<'_>,
    ) -> Result<HandlerAction, ProxyError> {
        let original_headers = ctx.headers;
        let request_id = &ctx.request_id;

        // Read list_rewrite from resolved bucket in extensions
        let list_rewrite = ctx.resolved_bucket().and_then(|r| r.list_rewrite.as_ref());

        // Read operation from extensions
        let operation = ctx.operation().ok_or_else(|| {
            ProxyError::Internal(
                "S3Operation not in context -- is S3OpParser middleware registered?".into(),
            )
        })?;

        // ListBuckets has no bucket config -- read from ResolvedBucketList extension.
        if matches!(operation, S3Operation::ListBuckets) {
            let bucket_list = ctx.extensions.get::<ResolvedBucketList>().ok_or_else(|| {
                ProxyError::Internal(
                    "ResolvedBucketList not in context -- is BucketResolver middleware registered?"
                        .into(),
                )
            })?;
            tracing::info!(count = bucket_list.buckets.len(), "listing virtual buckets");
            let xml = ListAllMyBucketsResult {
                owner: bucket_list.owner.clone(),
                buckets: BucketList {
                    buckets: bucket_list.buckets.clone(),
                },
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
        let bucket_config = &ctx
            .resolved_bucket()
            .ok_or_else(|| {
                ProxyError::Internal(
                    "BucketConfig not in context -- is BucketResolver middleware registered?"
                        .into(),
                )
            })?
            .config;

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
                    operation: operation.clone(),
                    bucket_config: bucket_config.clone(),
                    original_headers: original_headers.clone(),
                    request_id: request_id.to_string(),
                    response_headers: HeaderMap::new(),
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
            response_headers: HeaderMap::new(),
            request_id: request_id.to_string(),
        })
    }

    /// LIST via object_store's `PaginatedListStore`.
    ///
    /// Pagination is pushed to the backend -- only one page of results is fetched
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
            headers: raw_resp.headers,
            body: ProxyResponseBody::from_bytes(raw_resp.body),
        })
    }
}

impl<B, F> Dispatch for ProxyGateway<B, F>
where
    B: ProxyBackend,
    F: MaybeSend + MaybeSync,
{
    fn dispatch<'a>(&'a self, ctx: RequestContext<'a>) -> DispatchFuture<'a> {
        Box::pin(async move { self.dispatch_operation(&ctx).await })
    }
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
    use crate::forwarder::{ForwardResponse, Forwarder};
    use crate::registry::{BucketRegistry, CredentialRegistry, ResolvedBucket};
    use crate::types::{ResolvedIdentity, RoleConfig, StoredCredential};
    use object_store::list::PaginatedListStore;
    use object_store::signer::Signer;
    use std::collections::HashMap;
    use std::sync::Arc;

    // -- Mocks ---------------------------------------------------------------

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
            cors: None,
        }
    }

    struct MockForwarder;

    impl Forwarder<()> for MockForwarder {
        type ResponseBody = ();
        async fn forward(
            &self,
            _request: ForwardRequest,
            _body: (),
        ) -> Result<ForwardResponse<()>, ProxyError> {
            unimplemented!("not needed for resolve_request tests")
        }
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    fn gateway() -> ProxyGateway<MockBackend, MockForwarder> {
        ProxyGateway::new(MockBackend, MockForwarder, None)
            .with_s3_defaults(MockRegistry, MockCreds)
    }

    // Helper to run the middleware chain and get a HandlerAction.
    async fn resolve_request(
        gw: &ProxyGateway<MockBackend, MockForwarder>,
        method: Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> HandlerAction {
        let request_id = "test-request-id".to_string();
        let ctx = RequestContext {
            method: &method,
            path,
            query,
            headers,
            source_ip: None,
            request_id,
            extensions: http::Extensions::new(),
        };
        let next = Next::new(&gw.middleware, gw);
        match next.run(ctx).await {
            Ok(action) => action,
            Err(err) => HandlerAction::Response(error_response(&err, path, "test", false)),
        }
    }

    // -- Tests ---------------------------------------------------------------

    #[test]
    fn get_forward_preserves_range_header() {
        run(async {
            let gw = gateway();
            let mut headers = HeaderMap::new();
            headers.insert("range", "bytes=0-99".parse().unwrap());
            let action =
                resolve_request(&gw, Method::GET, "/test-bucket/key.txt", None, &headers).await;

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
            let action =
                resolve_request(&gw, Method::HEAD, "/test-bucket/key.txt", None, &headers).await;

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
            _ctx: crate::middleware::RequestContext<'a>,
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
            ctx: crate::middleware::RequestContext<'a>,
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
            let action =
                resolve_request(&gw, Method::GET, "/test-bucket/key.txt", None, &headers).await;

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
            let action =
                resolve_request(&gw, Method::GET, "/test-bucket/key.txt", None, &headers).await;

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
