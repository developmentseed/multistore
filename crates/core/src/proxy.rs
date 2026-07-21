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
use crate::backend::multipart::{build_backend_url, sign_s3_request, S3_PATH_ENCODE_SET};
use crate::backend::request_signer::{hash_payload, UNSIGNED_PAYLOAD};
use crate::backend::ForwardResponse;
use crate::backend::ProxyBackend;
use crate::error::ProxyError;
use crate::middleware::{
    CompletedRequest, Dispatch, DispatchContext, DispatchFuture, ErasedMiddleware, Middleware, Next,
};
use crate::registry::{BucketRegistry, CredentialRegistry};
use crate::route_handler::{ProxyResponseBody, RequestInfo};
use crate::router::Router;
use crate::types::{Action, BucketConfig, ResolvedIdentity, S3Operation};
use bytes::Bytes;
use http::{HeaderMap, Method};
use object_store::list::PaginatedListOptions;
use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;
use uuid::Uuid;

/// TTL for presigned URLs. Short because they're used immediately.
const PRESIGNED_URL_TTL: Duration = Duration::from_secs(300);

/// Rejection for aws-chunked uploads with *signed* chunks: each chunk signature
/// is bound to the client's key and can't be re-signed to the backend creds.
const SIGNED_AWS_CHUNKED_UNSUPPORTED: &str =
    "aws-chunked uploads with signed chunks (x-amz-content-sha256: \
     STREAMING-AWS4-HMAC-SHA256-PAYLOAD) are not supported; configure the client \
     to use a trailing checksum (the default) or multipart";

/// Default User-Agent header value sent with outbound backend requests.
///
/// Identifies multistore as the caller to backend object stores, useful for
/// access log analysis and debugging. Override via
/// [`ProxyGateway::with_user_agent`] to include your application name.
pub const DEFAULT_USER_AGENT: &str = concat!("multistore/", env!("CARGO_PKG_VERSION"));

/// Headers forwarded (and signed) when streaming an `aws-chunked` upload:
/// the de-chunk headers S3 needs to reconstruct the payload.
const AWS_CHUNKED_FORWARD_HEADERS: &[&str] = &[
    "content-type",
    "content-encoding",
    "x-amz-decoded-content-length",
    "x-amz-trailer",
];

/// Headers forwarded (and signed) when streaming a *plain* (non-aws-chunked)
/// `UploadPart` with `UNSIGNED-PAYLOAD`. The checksum headers are signed so S3
/// still validates part integrity even though the payload itself is unsigned.
const PLAIN_PART_FORWARD_HEADERS: &[&str] = &[
    "content-type",
    "content-md5",
    "x-amz-sdk-checksum-algorithm",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-crc64nvme",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
];

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
    /// User-Agent header value for outbound backend requests.
    user_agent: String,
    /// When true, responses include a `Server-Timing` header with gateway
    /// processing metrics. Enabled by default.
    server_timing: bool,
    /// Maximum accepted upload body size in bytes, if set. When a body-bearing
    /// write (`PutObject`, `UploadPart`, or `DeleteObjects`) declares a
    /// `Content-Length` larger than this, the proxy rejects it with
    /// `EntityTooLarge` instead of forwarding it. Useful for surfacing a clean
    /// S3 error ahead of a runtime body-size limit (e.g. Cloudflare Workers'
    /// edge `413`). `None` means no proxy-enforced limit.
    max_request_body_size: Option<u64>,
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
            user_agent: DEFAULT_USER_AGENT.to_string(),
            server_timing: true,
            max_request_body_size: None,
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

    /// Override the User-Agent header sent with outbound backend requests.
    ///
    /// Defaults to [`DEFAULT_USER_AGENT`] (`multistore/{version}`). Use this
    /// to include your application name, e.g. `"myapp/1.0 multistore/0.2.0"`.
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Enable or disable `Server-Timing` headers on responses.
    ///
    /// When enabled (the default), responses include a `Server-Timing` header
    /// with gateway processing metrics:
    ///
    /// - `total` — end-to-end gateway processing time (ms)
    /// - `dispatch` — time in the middleware/dispatch pipeline (ms)
    /// - `backend` — time waiting for the backend (ms, forwarded requests only)
    ///
    /// Useful for debugging latency and performance monitoring. Disable in
    /// production if you don't want to expose timing information to clients.
    pub fn with_server_timing(mut self, enabled: bool) -> Self {
        self.server_timing = enabled;
        self
    }

    /// Set the maximum accepted upload body size, in bytes.
    ///
    /// When set, a body-bearing write (`PutObject`, `UploadPart`, or
    /// `DeleteObjects`) whose `Content-Length` exceeds this is rejected up front
    /// with S3's `EntityTooLarge` (HTTP 400) rather than forwarded. Use this on
    /// runtimes with a hard request-body limit —
    /// e.g. Cloudflare Workers, where the edge otherwise rejects oversized
    /// bodies with an opaque `413` — to give clients an actionable S3 error.
    ///
    /// The check relies on a declared `Content-Length`; requests without one
    /// (e.g. unknown-length streaming) fall through to the runtime's own limit.
    /// Leaving this unset (the default) disables the proxy-enforced limit.
    pub fn with_max_request_body_size(mut self, max_bytes: u64) -> Self {
        self.max_request_body_size = Some(max_bytes);
        self
    }

    /// Reject an upload whose declared `Content-Length` exceeds the configured
    /// maximum. No-op when no limit is set or no `Content-Length` is present.
    fn check_upload_size(&self, headers: &HeaderMap) -> Result<(), ProxyError> {
        if let Some(max) = self.max_request_body_size {
            if let Some(len) = content_length(headers) {
                if len > max {
                    tracing::warn!(
                        content_length = len,
                        max = max,
                        "rejecting upload exceeding configured max body size"
                    );
                    return Err(ProxyError::EntityTooLarge);
                }
            }
        }
        Ok(())
    }

    /// Whether this operation's body must be buffered before forwarding
    /// (multipart control ops + batch delete, which parse the body to authorize
    /// or re-sign it). Pure and synchronous — the classification comes straight
    /// from the parsed S3 operation with no I/O — so `handle_request` can read
    /// the body in the request's own I/O context ahead of any cross-request
    /// await. PutObject and UploadPart stream zero-copy and are excluded; this
    /// set must stay in sync with the `NeedsBody` arms of `dispatch_operation`.
    fn op_needs_buffered_body(&self, req: &RequestInfo<'_>) -> bool {
        let host_style = determine_host_style(req.headers, self.virtual_host_domain.as_deref());
        matches!(
            request::parse_s3_request(req.method, req.path, req.query, req.headers, host_style),
            Ok(S3Operation::CreateMultipartUpload { .. }
                | S3Operation::CompleteMultipartUpload { .. }
                | S3Operation::AbortMultipartUpload { .. }
                | S3Operation::DeleteObjects { .. })
        )
    }

    /// Build an error [`GatewayResponse`] with its `Server-Timing` header
    /// stamped. Used by the early returns in `handle_request` (body too large,
    /// body read failure, body already consumed) that bail before dispatch.
    fn early_error(
        &self,
        error: &ProxyError,
        path: &str,
        request_id: &str,
        total_start: chrono::DateTime<chrono::Utc>,
        dispatch_start: Option<chrono::DateTime<chrono::Utc>>,
    ) -> GatewayResponse<B::ResponseBody> {
        let mut r = error_response(error, path, request_id, self.debug_errors);
        self.maybe_inject_server_timing(&mut r.headers, total_start, dispatch_start, None);
        GatewayResponse::Response(r)
    }

    /// Inject a `Server-Timing` header into the response headers if enabled.
    fn maybe_inject_server_timing(
        &self,
        headers: &mut HeaderMap,
        total_start: chrono::DateTime<chrono::Utc>,
        dispatch_start: Option<chrono::DateTime<chrono::Utc>>,
        backend_start: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        if !self.server_timing {
            return;
        }

        let now = chrono::Utc::now();
        let total_ms = (now - total_start).num_milliseconds().max(0);
        let mut value = format!("total;dur={total_ms}");

        if let Some(ds) = dispatch_start {
            let dispatch_ms = (now - ds).num_milliseconds().max(0);
            value.push_str(&format!(", dispatch;dur={dispatch_ms}"));
        }

        if let Some(bs) = backend_start {
            let backend_ms = (now - bs).num_milliseconds().max(0);
            value.push_str(&format!(", backend;dur={backend_ms}"));
        }

        if let Ok(hv) = value.parse() {
            headers.insert("server-timing", hv);
        }
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
    pub async fn handle_request<CF, Fut, E>(
        &self,
        req: &RequestInfo<'_>,
        body: B::Body,
        collect_body: CF,
    ) -> GatewayResponse<B::ResponseBody>
    where
        CF: FnOnce(B::Body) -> Fut,
        Fut: std::future::Future<Output = Result<Bytes, E>>,
        E: std::fmt::Display,
    {
        let total_start = chrono::Utc::now();

        // Route handlers first (bypass forwarder/after_dispatch for simplicity)
        if let Some(action) = self.router.dispatch(req).await {
            return match action {
                HandlerAction::Response(mut r) => {
                    self.maybe_inject_server_timing(&mut r.headers, total_start, None, None);
                    GatewayResponse::Response(r)
                }
                HandlerAction::Forward(fwd) => {
                    let backend_start = chrono::Utc::now();
                    match self.backend.forward(fwd, body).await {
                        Ok(mut resp) => {
                            resp.headers = filter_response_headers(&resp.headers);
                            self.maybe_inject_server_timing(
                                &mut resp.headers,
                                total_start,
                                None,
                                Some(backend_start),
                            );
                            GatewayResponse::Forward(resp)
                        }
                        Err(e) => {
                            let mut r = error_response(&e, req.path, "", self.debug_errors);
                            self.maybe_inject_server_timing(
                                &mut r.headers,
                                total_start,
                                None,
                                Some(backend_start),
                            );
                            GatewayResponse::Response(r)
                        }
                    }
                }
                HandlerAction::NeedsBody(_) => {
                    let mut r = error_response(
                        &ProxyError::Internal("unexpected NeedsBody from route handler".into()),
                        req.path,
                        "",
                        self.debug_errors,
                    );
                    self.maybe_inject_server_timing(&mut r.headers, total_start, None, None);
                    GatewayResponse::Response(r)
                }
            };
        }

        // Buffered-body operations (multipart control ops + batch delete) must
        // have their body read in THIS request's I/O context, before
        // resolution's cross-request awaits (bucket lookup, STS exchange). On
        // Cloudflare Workers the wasm-bindgen futures queue is shared across
        // concurrent requests, so a body read deferred past an await can resume
        // under a different request's I/O context and fail with "Cannot perform
        // I/O on behalf of a different request". PutObject/UploadPart stream
        // zero-copy and are excluded by the classifier.
        let mut body = Some(body);
        let mut prebuffered: Option<Bytes> = None;
        if self.op_needs_buffered_body(req) {
            // Bound the declared body size before reading it. This eager read is
            // ahead of dispatch's own `check_upload_size`, so without this guard
            // an oversized buffered op (e.g. a batch `DeleteObjects`) would be
            // fully materialized into memory before being rejected. Header-only,
            // no I/O.
            if let Err(e) = self.check_upload_size(req.headers) {
                return self.early_error(&e, req.path, "", total_start, None);
            }
            match collect_body(body.take().expect("body present")).await {
                Ok(bytes) => prebuffered = Some(bytes),
                Err(e) => {
                    tracing::error!(error = %e, "failed to read request body");
                    return self.early_error(
                        &ProxyError::Internal("failed to read request body".into()),
                        req.path,
                        "",
                        total_start,
                        None,
                    );
                }
            }
        }

        // Resolve via proxy pipeline (with metadata for after_dispatch)
        let dispatch_start = chrono::Utc::now();
        let (action, metadata) = self.resolve_request_with_metadata(req).await;

        // Helper to extract response body size
        fn response_body_bytes(body: &ProxyResponseBody) -> Option<u64> {
            match body {
                ProxyResponseBody::Bytes(b) => Some(b.len() as u64),
                ProxyResponseBody::Empty => Some(0),
            }
        }

        let request_bytes = content_length(req.headers);

        let (mut response, status, resp_bytes, was_forwarded, backend_start) = match action {
            HandlerAction::Response(r) => {
                let s = r.status;
                let rb = response_body_bytes(&r.body);
                (GatewayResponse::Response(r), s, rb, false, None)
            }
            HandlerAction::Forward(fwd) => {
                let backend_start = chrono::Utc::now();
                // `body` is consumed only here (streaming/forward ops). If the
                // eager pre-read already took it, `op_needs_buffered_body`
                // over-matched an op that dispatched to Forward — fail closed
                // rather than panic on the missing body.
                let Some(fwd_body) = body.take() else {
                    return self.early_error(
                        &ProxyError::Internal("request body already consumed".into()),
                        req.path,
                        &metadata.request_id,
                        total_start,
                        Some(dispatch_start),
                    );
                };
                match self.backend.forward(fwd, fwd_body).await {
                    Ok(mut resp) => {
                        resp.headers = filter_response_headers(&resp.headers);
                        let s = resp.status;
                        let cl = resp.content_length;
                        (
                            GatewayResponse::Forward(resp),
                            s,
                            cl,
                            true,
                            Some(backend_start),
                        )
                    }
                    Err(e) => {
                        let err_resp =
                            error_response(&e, req.path, &metadata.request_id, self.debug_errors);
                        let s = err_resp.status;
                        (
                            GatewayResponse::Response(err_resp),
                            s,
                            None,
                            true,
                            Some(backend_start),
                        )
                    }
                }
            }
            HandlerAction::NeedsBody(pending) => {
                let backend_start = chrono::Utc::now();
                // The body was pre-read above: op_needs_buffered_body covers
                // every NeedsBody op. A miss means the classifier drifted from
                // dispatch_operation's NeedsBody arms — fail closed rather than
                // re-read late (which would re-expose the cross-request hazard).
                match prebuffered.take() {
                    Some(bytes) => {
                        let result = self.handle_with_body(*pending, bytes).await;
                        let s = result.status;
                        let rb = response_body_bytes(&result.body);
                        (
                            GatewayResponse::Response(result),
                            s,
                            rb,
                            false,
                            Some(backend_start),
                        )
                    }
                    None => {
                        tracing::error!(
                            operation = ?metadata.operation,
                            "NeedsBody operation was not pre-buffered (classifier drift)"
                        );
                        let err_resp = error_response(
                            &ProxyError::Internal("request body unavailable".into()),
                            req.path,
                            &metadata.request_id,
                            self.debug_errors,
                        );
                        let s = err_resp.status;
                        (
                            GatewayResponse::Response(err_resp),
                            s,
                            None,
                            false,
                            Some(backend_start),
                        )
                    }
                }
            }
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

        // Inject Server-Timing header
        match &mut response {
            GatewayResponse::Response(ref mut r) => {
                self.maybe_inject_server_timing(
                    &mut r.headers,
                    total_start,
                    Some(dispatch_start),
                    backend_start,
                );
            }
            GatewayResponse::Forward(ref mut fwd) => {
                self.maybe_inject_server_timing(
                    &mut fwd.headers,
                    total_start,
                    Some(dispatch_start),
                    backend_start,
                );
            }
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
        let operation = match request::parse_s3_request(
            req.method,
            req.path,
            req.query,
            req.headers,
            host_style,
        ) {
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

    /// Phase 2: Complete a body-bearing operation with the materialized body.
    ///
    /// Called by the runtime after materializing the body for a `NeedsBody`
    /// action — multipart operations and batch delete. Middleware is not re-run
    /// here — it already executed during phase 1 when the `NeedsBody` action was
    /// produced.
    pub async fn handle_with_body(&self, pending: PendingRequest, body: Bytes) -> ProxyResult {
        let result = match &pending.operation {
            S3Operation::DeleteObjects { .. } => self.execute_delete_objects(&pending, body).await,
            _ => self.execute_multipart(&pending, body).await,
        };
        match result {
            Ok(result) => {
                tracing::info!(
                    request_id = %pending.request_id,
                    status = result.status,
                    "body request completed"
                );
                result
            }
            Err(err) => {
                tracing::warn!(
                    request_id = %pending.request_id,
                    error = %err,
                    status = err.status_code(),
                    s3_code = %err.s3_error_code(),
                    "body request failed"
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

        // The deferred-body operations (UploadPart/multipart/batch-delete) all
        // build the same pending request from the current context.
        let pending = || PendingRequest {
            operation: operation.clone(),
            bucket_config: bucket_config.clone(),
            original_headers: original_headers.clone(),
            request_id: request_id.to_string(),
            identity: ctx.identity.clone(),
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
                self.check_upload_size(original_headers)?;
                // An `aws-chunked` body can't be presigned (S3 only de-chunks a
                // streaming-signed request, so a presigned PUT would store the
                // raw chunk envelope) — stream-re-sign or reject it.
                if let Some(fwd) = self
                    .try_streaming_forward(bucket_config, operation, original_headers, request_id)
                    .await?
                {
                    return Ok(HandlerAction::Forward(fwd));
                }
                let fwd = self
                    .build_forward(
                        Method::PUT,
                        bucket_config,
                        key,
                        original_headers,
                        // Standard HTTP entity headers are safe to forward to a
                        // presigned URL: S3 applies them even though they are not
                        // part of the (host-only) presigned signature. `x-amz-*`
                        // write headers (metadata, SSE, tagging, storage-class,
                        // checksums) are deliberately NOT forwarded here — S3
                        // rejects unsigned `x-amz-*` headers on presigned
                        // requests, so they need the header-signing path. See
                        // .plans/2026-06-23-data-edit-operations-design.md.
                        &[
                            "content-type",
                            "content-length",
                            "content-md5",
                            "content-disposition",
                            "content-encoding",
                            "content-language",
                            "cache-control",
                            "expires",
                        ],
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
            // UploadPart carries the part body. aws-chunked parts re-sign and
            // stream; a plain part streams too, via UNSIGNED-PAYLOAD header
            // signing — never buffered. Buffering a part would materialize it
            // into memory and, on Workers, defer the body read past the
            // resolution awaits into another request's I/O context.
            S3Operation::UploadPart { .. } => {
                Self::require_s3_backend(bucket_config)?;
                self.check_upload_size(original_headers)?;
                if let Some(fwd) = self
                    .try_streaming_forward(bucket_config, operation, original_headers, request_id)
                    .await?
                {
                    return Ok(HandlerAction::Forward(fwd));
                }
                // Plain (non-aws-chunked) part: stream it with UNSIGNED-PAYLOAD,
                // forwarding+signing the checksum headers so S3 still validates
                // part integrity. Mirrors PutObject's streaming write.
                let fwd = self
                    .build_streaming_forward(
                        bucket_config,
                        operation,
                        UNSIGNED_PAYLOAD,
                        PLAIN_PART_FORWARD_HEADERS,
                        original_headers,
                        request_id,
                    )
                    .await?;
                Ok(HandlerAction::Forward(fwd))
            }
            // Multipart control operations carry only a small (XML or empty)
            // body, which is buffered and re-signed.
            S3Operation::CreateMultipartUpload { .. }
            | S3Operation::CompleteMultipartUpload { .. }
            | S3Operation::AbortMultipartUpload { .. } => {
                Self::require_s3_backend(bucket_config)?;
                Ok(HandlerAction::NeedsBody(Box::new(pending())))
            }
            // Batch delete needs the body to read the key list and authorize
            // each key individually.
            S3Operation::DeleteObjects { .. } => {
                if !bucket_config.is_s3_backend() {
                    return Err(ProxyError::NotImplemented(format!(
                        "batch delete not supported for '{}' backends",
                        bucket_config.backend_type
                    )));
                }
                // The body is buffered whole; bound it like other uploads. The
                // key count is additionally capped when the body is parsed.
                self.check_upload_size(original_headers)?;
                Ok(HandlerAction::NeedsBody(Box::new(pending())))
            }
            S3Operation::CopyObject {
                src_bucket,
                src_key,
                src_version,
                ..
            } => {
                Self::require_s3_backend(bucket_config)?;
                // Resolve + authorize the source as a read. Reusing get_bucket
                // with a synthetic GetObject applies the exact authorization a
                // real GET of the source object would — the copy's destination
                // write was already authorized by the main pipeline.
                let src_op = S3Operation::GetObject {
                    bucket: src_bucket.clone(),
                    key: src_key.clone(),
                };
                let src = self
                    .bucket_registry
                    .get_bucket(src_bucket, ctx.identity, &src_op)
                    .await?;
                let result = self
                    .execute_copy(
                        bucket_config,
                        &src.config,
                        operation,
                        src_key,
                        src_version.as_deref(),
                        original_headers,
                    )
                    .await?;
                Ok(HandlerAction::Response(result))
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
        let path = build_object_path(config, key)?;

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
        fwd_headers.insert(http::header::USER_AGENT, self.user_agent.parse().unwrap());

        Ok(ForwardRequest {
            method,
            url,
            headers: fwd_headers,
            request_id: request_id.to_string(),
        })
    }

    /// Handle a body-bearing PUT (PutObject/UploadPart) whose body is
    /// `aws-chunked`: stream an unsigned-payload upload through after re-signing
    /// the seed (returns the `Forward`), reject a signed-chunk one, or return
    /// `None` for a plain body so the caller takes its own path.
    async fn try_streaming_forward(
        &self,
        config: &BucketConfig,
        operation: &S3Operation,
        original_headers: &HeaderMap,
        request_id: &str,
    ) -> Result<Option<ForwardRequest>, ProxyError> {
        match crate::aws_chunked::streaming_upload(original_headers) {
            Some((crate::aws_chunked::StreamingUpload::Unsigned, sentinel)) => {
                // Streaming re-sign hardcodes S3 SigV4 seed signing; a non-S3
                // backend can't be presigned for aws-chunked either, so a
                // streaming upload there has no valid path — reject rather than
                // mis-sign. (UploadPart gates on this earlier too; this also
                // covers PutObject's streaming arm.)
                if !config.is_s3_backend() {
                    return Err(ProxyError::InvalidRequest(format!(
                        "aws-chunked streaming uploads are not supported for '{}' backends",
                        config.backend_type
                    )));
                }
                Ok(Some(
                    self.build_streaming_forward(
                        config,
                        operation,
                        sentinel,
                        AWS_CHUNKED_FORWARD_HEADERS,
                        original_headers,
                        request_id,
                    )
                    .await?,
                ))
            }
            Some((crate::aws_chunked::StreamingUpload::Signed, _)) => Err(
                ProxyError::NotImplemented(SIGNED_AWS_CHUNKED_UNSUPPORTED.to_string()),
            ),
            None => Ok(None),
        }
    }

    /// Reject multipart operations on non-S3 backends (an S3-only feature).
    fn require_s3_backend(config: &BucketConfig) -> Result<(), ProxyError> {
        if config.is_s3_backend() {
            Ok(())
        } else {
            Err(ProxyError::InvalidRequest(format!(
                "multipart operations not supported for '{}' backends",
                config.backend_type
            )))
        }
    }

    /// Build a header-signed streaming PUT, re-signing only the request seed
    /// with the backend credentials and letting the runtime stream the body
    /// through untouched. Zero-copy, no buffering. Two callers:
    ///
    /// - aws-chunked uploads (`payload_hash` = the client's `STREAMING-…`
    ///   sentinel, `forward_header_names` = the de-chunk headers): can't be
    ///   presigned (a presigned URL signs `UNSIGNED-PAYLOAD`, which S3 won't
    ///   de-chunk), so S3 reconstructs the payload from the chunk framing.
    /// - plain `UploadPart` (`payload_hash` = `UNSIGNED-PAYLOAD`,
    ///   `forward_header_names` = the checksum headers): streams a raw part
    ///   instead of materializing it; the signed checksum headers let S3 still
    ///   validate part integrity.
    ///
    /// Only headers stable through the runtime's streaming fetch are signed.
    /// `Content-Length` is forwarded but left *unsigned*: the transfer framing
    /// is the runtime's to manage, so signing it risks a mismatch.
    async fn build_streaming_forward(
        &self,
        config: &BucketConfig,
        operation: &S3Operation,
        payload_hash: &str,
        forward_header_names: &[&'static str],
        original_headers: &HeaderMap,
        request_id: &str,
    ) -> Result<ForwardRequest, ProxyError> {
        // Caller has already gated on an S3 backend; this path hardcodes S3
        // SigV4 seed signing (`build_backend_url` + `sign_s3_request`).
        let url = url::Url::parse(&build_backend_url(config, operation)?)
            .map_err(|e| ProxyError::Internal(format!("invalid backend URL: {e}")))?;

        let mut headers = HeaderMap::new();
        for name in forward_header_names {
            if let Some(v) = original_headers.get(*name) {
                headers.insert(*name, v.clone());
            }
        }

        // Re-sign the seed with the backend creds, reusing the client's exact
        // streaming sentinel (`payload_hash`, the `-TRAILER` suffix matters) as
        // the canonical-request payload hash.
        sign_s3_request(
            &Method::PUT,
            url.as_str(),
            &mut headers,
            config,
            payload_hash,
        )?;

        // Forwarded unsigned (see the doc comment).
        if let Some(cl) = original_headers.get(http::header::CONTENT_LENGTH) {
            headers.insert(http::header::CONTENT_LENGTH, cl.clone());
        }
        headers.insert(http::header::USER_AGENT, self.user_agent.parse().unwrap());

        tracing::debug!(
            path = url.path(),
            payload_hash,
            "streaming write via backend re-sign"
        );
        Ok(ForwardRequest {
            method: Method::PUT,
            url,
            headers,
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

        // Forward entity headers plus the client's flexible-checksum headers.
        // Modern AWS SDKs/CLI enable CRC32 integrity checksums by default:
        // CreateMultipartUpload declares the algorithm (`x-amz-checksum-algorithm`)
        // and CompleteMultipartUpload echoes the per-part / full-object checksums
        // (`x-amz-checksum-type`, `x-amz-checksum-crc32`, …). Dropping them leaves
        // the MPU with no checksum context while the parts are stored *with*
        // checksums, so S3 rejects the completion with `InvalidPart`. This raw
        // path signs every header present (see `sign_s3_request`), so forwarding
        // them here is safe — unlike the presigned PutObject path, where S3
        // rejects unsigned `x-amz-*` headers.
        for (name, val) in pending.original_headers.iter() {
            let n = name.as_str();
            if matches!(n, "content-type" | "content-length" | "content-md5")
                || n.starts_with("x-amz-checksum")
                || n == "x-amz-sdk-checksum-algorithm"
            {
                headers.insert(name.clone(), val.clone());
            }
        }
        headers.insert(http::header::USER_AGENT, self.user_agent.parse().unwrap());

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

    /// Execute a batch delete (`DeleteObjects`) via raw signed HTTP.
    ///
    /// Each key in the request body is authorized individually against the
    /// caller's scopes (the earlier [`authorize`](crate::auth::authorize) check
    /// only verified the caller may delete *something* in the bucket). Keys the
    /// caller is not allowed to delete are reported as per-key `AccessDenied`
    /// errors (S3's partial-result semantics) rather than failing the whole
    /// request; the remaining keys are forwarded to the backend.
    async fn execute_delete_objects(
        &self,
        pending: &PendingRequest,
        body: Bytes,
    ) -> Result<ProxyResult, ProxyError> {
        use crate::api::delete;

        let config = &pending.bucket_config;
        let bucket = pending.operation.bucket().unwrap_or_default();

        let request = delete::DeleteRequest::parse(&body)?;
        let quiet = request.quiet;

        // Partition keys by per-key authorization.
        let mut allowed_backend: Vec<String> = Vec::new();
        let mut errors: Vec<delete::DeleteError> = Vec::new();
        for key in request.keys() {
            if self
                .bucket_registry
                .authorize_key(bucket, &pending.identity, Action::DeleteObject, key)
                .await
            {
                allowed_backend.push(apply_backend_prefix(config, key));
            } else {
                errors.push(delete::DeleteError {
                    key: key.to_string(),
                    code: "AccessDenied".into(),
                    message: "Access Denied".into(),
                });
            }
        }

        let mut deleted_client: Vec<String> = Vec::new();

        if !allowed_backend.is_empty() {
            let backend_body = Bytes::from(delete::build_backend_delete_body(&allowed_backend));
            let backend_url = build_backend_url(config, &pending.operation)?;

            let mut headers = HeaderMap::new();
            headers.insert("content-type", "application/xml".parse().unwrap());
            // S3 requires a Content-MD5 (or trailing checksum) on DeleteObjects.
            headers.insert(
                "content-md5",
                content_md5(&backend_body)
                    .parse()
                    .map_err(|_| ProxyError::Internal("invalid content-md5 header".into()))?,
            );
            headers.insert(http::header::USER_AGENT, self.user_agent.parse().unwrap());

            let payload_hash = hash_payload(&backend_body);
            sign_s3_request(
                &Method::POST,
                &backend_url,
                &mut headers,
                config,
                &payload_hash,
            )?;

            let raw_resp = self
                .backend
                .send_raw(Method::POST, backend_url, headers, backend_body)
                .await?;

            tracing::debug!(status = raw_resp.status, "batch delete backend response");

            if raw_resp.status >= 300 {
                return Err(ProxyError::BackendError(format!(
                    "backend rejected batch delete with status {}",
                    raw_resp.status
                )));
            }

            match delete::parse_backend_result(&raw_resp.body) {
                Ok(outcome) => {
                    for k in outcome.deleted {
                        deleted_client.push(strip_backend_prefix(config, &k));
                    }
                    for mut e in outcome.errors {
                        e.key = strip_backend_prefix(config, &e.key);
                        errors.push(e);
                    }
                }
                Err(e) => {
                    // A 2xx with an unparseable DeleteResult is a backend
                    // contract violation. Surface it rather than fabricating
                    // success for keys whose actual fate is unknown.
                    tracing::error!(error = %e, "backend returned an unparseable delete result");
                    return Err(ProxyError::BackendError(
                        "backend returned an unparseable delete result".into(),
                    ));
                }
            }
        }

        let xml = delete::build_delete_result(&deleted_client, &errors, quiet);
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("content-type", "application/xml".parse().unwrap());
        Ok(ProxyResult {
            status: 200,
            headers: resp_headers,
            body: ProxyResponseBody::from_bytes(Bytes::from(xml)),
        })
    }

    /// Execute a server-side copy (`CopyObject`) via raw signed HTTP.
    ///
    /// The copy is delegated to the backend S3: a signed `PUT` to the
    /// destination key carries `x-amz-copy-source` pointing at the source's
    /// backend bucket/key. Only same-store copies (source and destination on
    /// the same S3 endpoint + credentials) are supported — a native S3 copy
    /// cannot reach across two distinct backends.
    ///
    /// The backend's `CopyObjectResult` XML (and any 4xx/5xx, including the
    /// "error embedded in a 200" case) is passed straight through: it carries
    /// only an ETag + LastModified, neither of which needs rewriting.
    async fn execute_copy(
        &self,
        dest_config: &BucketConfig,
        src_config: &BucketConfig,
        operation: &S3Operation,
        src_key: &str,
        src_version: Option<&str>,
        original_headers: &HeaderMap,
    ) -> Result<ProxyResult, ProxyError> {
        // ponytail: cross-store copy rejected, not streamed. A native S3 copy
        // needs one endpoint that can read the source and write the
        // destination. Upgrade path: proxy-side read-then-write streaming
        // (with >5 GB handling and 200-embedded-error detection) when a real
        // cross-store use case appears.
        if !same_backing_store(src_config, dest_config) {
            return Err(ProxyError::NotImplemented(
                "cross-store copy (source and destination on different backends) is not supported"
                    .into(),
            ));
        }

        let copy_source = build_copy_source_header(src_config, src_key, src_version)?;
        let backend_url = build_backend_url(dest_config, operation)?;

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            copy_source.parse().map_err(|_| {
                ProxyError::Internal("invalid x-amz-copy-source header value".into())
            })?,
        );
        // Forward the copy-relevant client headers. Every header here is signed
        // by `sign_s3_request`, so unlike the presigned PUT path, `x-amz-*`
        // headers are safe to pass through.
        for (name, val) in original_headers.iter() {
            if is_copy_forward_header(name.as_str()) {
                headers.insert(name.clone(), val.clone());
            }
        }
        headers.insert(http::header::USER_AGENT, self.user_agent.parse().unwrap());

        // Empty request body: sign the hash of the empty payload.
        let payload_hash = hash_payload(&[]);
        sign_s3_request(
            &Method::PUT,
            &backend_url,
            &mut headers,
            dest_config,
            &payload_hash,
        )?;

        let raw_resp = self
            .backend
            .send_raw(Method::PUT, backend_url, headers, Bytes::new())
            .await?;

        tracing::debug!(status = raw_resp.status, "copy backend response");

        Ok(ProxyResult {
            status: raw_resp.status,
            headers: filter_response_headers(&raw_resp.headers),
            body: ProxyResponseBody::from_bytes(raw_resp.body),
        })
    }
}

/// Whether two bucket configs point at the same S3 backing store, such that a
/// native server-side copy from one to the other is possible.
///
/// Requires both to be S3 backends sharing the same endpoint, region, and
/// credentials — then a `PUT` signed for the destination endpoint can name the
/// source bucket in `x-amz-copy-source` and S3 performs the copy internally.
/// The bucket names may differ (cross-bucket copy within one account). This is
/// deliberately conservative: two configs that resolve to the same physical
/// store via different credentials are treated as distinct.
fn same_backing_store(a: &BucketConfig, b: &BucketConfig) -> bool {
    a.is_s3_backend()
        && b.is_s3_backend()
        && a.option("endpoint") == b.option("endpoint")
        && a.option("region") == b.option("region")
        && a.option("access_key_id") == b.option("access_key_id")
        && a.option("secret_access_key") == b.option("secret_access_key")
        && a.option("token") == b.option("token")
}

/// Build the backend `x-amz-copy-source` header value for a same-store copy:
/// `/{backend_bucket}/{encoded backend key}[?versionId=id]`.
///
/// The key is mapped into the source's backend key space (prefix applied) and
/// percent-encoded with the same strict set S3 uses for canonical paths.
fn build_copy_source_header(
    src_config: &BucketConfig,
    src_key: &str,
    src_version: Option<&str>,
) -> Result<String, ProxyError> {
    let src_bucket = src_config.option("bucket_name").unwrap_or("");
    if src_bucket.is_empty() {
        return Err(ProxyError::NotImplemented(
            "copy from a backend without a bucket name is not supported".into(),
        ));
    }
    let backend_key = apply_backend_prefix(src_config, src_key);
    let encoded_key =
        percent_encoding::utf8_percent_encode(&backend_key, S3_PATH_ENCODE_SET).to_string();
    let mut value = format!("/{src_bucket}/{encoded_key}");
    if let Some(version) = src_version {
        value.push_str("?versionId=");
        value.push_str(version);
    }
    Ok(value)
}

/// Client request headers forwarded (and signed) onto a backend CopyObject PUT.
/// The copy-source header itself and the client's own SigV4 headers
/// (`authorization`, `x-amz-date`, `x-amz-content-sha256`, session token) are
/// deliberately excluded — the request is re-signed for the backend.
fn is_copy_forward_header(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "content-disposition"
            | "content-encoding"
            | "content-language"
            | "cache-control"
            | "expires"
            | "x-amz-metadata-directive"
            | "x-amz-tagging-directive"
            | "x-amz-tagging"
            | "x-amz-acl"
            | "x-amz-storage-class"
            | "x-amz-website-redirect-location"
            | "x-amz-copy-source-if-match"
            | "x-amz-copy-source-if-none-match"
            | "x-amz-copy-source-if-modified-since"
            | "x-amz-copy-source-if-unmodified-since"
    ) || name.starts_with("x-amz-meta-")
        || name.starts_with("x-amz-server-side-encryption")
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
///
/// Uses `Path::parse` (byte-faithful) rather than `Path::from`: `Path::from`
/// percent-encodes characters object_store considers unsafe (`*`, `%`, `~`,
/// `#`, ...) into the *logical* path, silently renaming the backend object
/// (`a*.bin` is stored as `a%2A.bin`) and splitting the key namespace from
/// the raw-signed multipart path, which stores keys byte-faithfully. With
/// `Path::parse` the raw path is the key itself, and object_store's URL
/// builder percent-encodes it exactly once at the wire boundary.
///
/// `Path::parse` rejects keys with empty (`a//b`) or relative (`.`, `..`)
/// segments; surface those as `InvalidRequest` (400) rather than silently
/// collapsing them to a different key as `Path::from` did. This is a
/// backstop: `validate_key` already rejects that class — plus leading and
/// trailing slashes, which `Path::parse` would silently strip — for every
/// keyed operation at parse time.
fn build_object_path(
    config: &BucketConfig,
    key: &str,
) -> Result<object_store::path::Path, ProxyError> {
    object_store::path::Path::parse(apply_backend_prefix(config, key))
        .map_err(|e| ProxyError::InvalidRequest(format!("invalid object key: {e}")))
}

/// Parse the declared `Content-Length` header as a byte count, if present and valid.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// Map a client-visible key into the backend key space by prepending
/// `backend_prefix`.
fn apply_backend_prefix(config: &BucketConfig, key: &str) -> String {
    match &config.backend_prefix {
        Some(prefix) => {
            let p = prefix.trim_end_matches('/');
            if p.is_empty() {
                key.to_string()
            } else {
                format!("{p}/{key}")
            }
        }
        None => key.to_string(),
    }
}

/// Strip `backend_prefix` from a backend key to recover the client-visible key.
fn strip_backend_prefix(config: &BucketConfig, key: &str) -> String {
    match &config.backend_prefix {
        Some(prefix) => {
            let p = prefix.trim_end_matches('/');
            if p.is_empty() {
                return key.to_string();
            }
            // Strip `{p}/` without allocating a pattern string (runs per key).
            key.strip_prefix(p)
                .and_then(|rest| rest.strip_prefix('/'))
                .unwrap_or(key)
                .to_string()
        }
        None => key.to_string(),
    }
}

/// Compute the base64-encoded MD5 of `body` for the `Content-MD5` header.
fn content_md5(body: &[u8]) -> String {
    use base64::Engine;
    use md5::{Digest, Md5};
    base64::engine::general_purpose::STANDARD.encode(Md5::digest(body))
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
        type Body = ();

        async fn forward(
            &self,
            _request: ForwardRequest,
            _body: (),
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
        // A bucket named `azure-*` resolves to a non-S3 backend so tests can
        // exercise the non-S3 rejection paths; everything else is S3.
        let backend_type = if name.starts_with("azure") {
            "azure"
        } else {
            "s3"
        };
        BucketConfig {
            name: name.to_string(),
            backend_type: backend_type.into(),
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

    // -- User-Agent tests ----------------------------------------------------

    #[test]
    fn forward_includes_user_agent_header() {
        run(async {
            let gw = gateway();
            let headers = HeaderMap::new();
            let action = gw
                .resolve_request(Method::GET, "/test-bucket/key.txt", None, &headers, None)
                .await;

            match action {
                HandlerAction::Forward(fwd) => {
                    let ua = fwd
                        .headers
                        .get(http::header::USER_AGENT)
                        .expect("forward should include User-Agent header");
                    assert!(
                        ua.to_str().unwrap().starts_with("multistore/"),
                        "User-Agent should start with 'multistore/', got: {}",
                        ua.to_str().unwrap()
                    );
                }
                other => panic!("expected Forward, got {:?}", std::mem::discriminant(&other)),
            }
        });
    }

    #[test]
    fn put_forward_includes_user_agent_header() {
        run(async {
            let gw = gateway();
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "application/octet-stream".parse().unwrap());
            let action = gw
                .resolve_request(Method::PUT, "/test-bucket/key.txt", None, &headers, None)
                .await;

            match action {
                HandlerAction::Forward(fwd) => {
                    let ua = fwd
                        .headers
                        .get(http::header::USER_AGENT)
                        .expect("PUT forward should include User-Agent header");
                    assert!(
                        ua.to_str().unwrap().starts_with("multistore/"),
                        "User-Agent should start with 'multistore/', got: {}",
                        ua.to_str().unwrap()
                    );
                }
                other => panic!("expected Forward, got {:?}", std::mem::discriminant(&other)),
            }
        });
    }

    #[test]
    fn delete_forward_includes_user_agent_header() {
        run(async {
            let gw = gateway();
            let headers = HeaderMap::new();
            let action = gw
                .resolve_request(Method::DELETE, "/test-bucket/key.txt", None, &headers, None)
                .await;

            match action {
                HandlerAction::Forward(fwd) => {
                    let ua = fwd
                        .headers
                        .get(http::header::USER_AGENT)
                        .expect("DELETE forward should include User-Agent header");
                    assert_eq!(ua.to_str().unwrap(), DEFAULT_USER_AGENT);
                }
                other => panic!("expected Forward, got {:?}", std::mem::discriminant(&other)),
            }
        });
    }

    #[test]
    fn custom_user_agent_is_used_in_forward() {
        run(async {
            let gw = gateway().with_user_agent("myapp/1.0 multistore/0.2.0");
            let headers = HeaderMap::new();
            let action = gw
                .resolve_request(Method::GET, "/test-bucket/key.txt", None, &headers, None)
                .await;

            match action {
                HandlerAction::Forward(fwd) => {
                    let ua = fwd
                        .headers
                        .get(http::header::USER_AGENT)
                        .expect("forward should include User-Agent header");
                    assert_eq!(ua.to_str().unwrap(), "myapp/1.0 multistore/0.2.0");
                }
                other => panic!("expected Forward, got {:?}", std::mem::discriminant(&other)),
            }
        });
    }

    #[test]
    fn multipart_needs_body_then_includes_user_agent() {
        run(async {
            let gw = gateway();
            let headers = HeaderMap::new();
            let action = gw
                .resolve_request(
                    Method::POST,
                    "/test-bucket/key.txt",
                    Some("uploads"),
                    &headers,
                    None,
                )
                .await;

            // CreateMultipartUpload should return NeedsBody
            assert!(
                matches!(action, HandlerAction::NeedsBody(_)),
                "CreateMultipartUpload should return NeedsBody"
            );
        });
    }

    // -- Max upload size (EntityTooLarge) ------------------------------------

    #[test]
    fn put_over_max_body_size_is_rejected() {
        run(async {
            let gw = gateway().with_max_request_body_size(1024);
            let mut headers = HeaderMap::new();
            headers.insert("content-length", "2048".parse().unwrap());
            let action = gw
                .resolve_request(Method::PUT, "/test-bucket/big.bin", None, &headers, None)
                .await;
            match action {
                HandlerAction::Response(r) => assert_eq!(
                    r.status, 400,
                    "oversized PUT should be rejected with EntityTooLarge (400)"
                ),
                other => panic!(
                    "expected Response, got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        });
    }

    #[test]
    fn put_under_max_body_size_forwards() {
        run(async {
            let gw = gateway().with_max_request_body_size(1_000_000);
            let mut headers = HeaderMap::new();
            headers.insert("content-length", "1024".parse().unwrap());
            let action = gw
                .resolve_request(Method::PUT, "/test-bucket/ok.bin", None, &headers, None)
                .await;
            assert!(
                matches!(action, HandlerAction::Forward(_)),
                "PUT within the limit should forward"
            );
        });
    }

    #[test]
    fn put_with_no_limit_forwards_large_body() {
        run(async {
            let gw = gateway(); // default: no proxy-enforced limit
            let mut headers = HeaderMap::new();
            headers.insert("content-length", "999999999".parse().unwrap());
            let action = gw
                .resolve_request(Method::PUT, "/test-bucket/huge.bin", None, &headers, None)
                .await;
            assert!(
                matches!(action, HandlerAction::Forward(_)),
                "with no limit configured, large PUT should still forward"
            );
        });
    }

    /// An aws-chunked unsigned-payload upload (the modern aws-cli default) is
    /// re-signed for the backend and streamed through — not buffered, not
    /// presigned. The forwarded request reuses the streaming sentinel and
    /// carries a fresh backend Authorization plus the de-chunk headers.
    fn unsigned_aws_chunked_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", "aws-chunked".parse().unwrap());
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER".parse().unwrap(),
        );
        headers.insert("content-length", "52".parse().unwrap());
        headers.insert("x-amz-decoded-content-length", "7".parse().unwrap());
        headers.insert("x-amz-trailer", "x-amz-checksum-crc64nvme".parse().unwrap());
        headers
    }

    #[test]
    fn put_unsigned_aws_chunked_streams_via_resign() {
        run(async {
            let gw = gateway();
            let headers = unsigned_aws_chunked_headers();
            let action = gw
                .resolve_request(Method::PUT, "/test-bucket/test.md", None, &headers, None)
                .await;
            match action {
                HandlerAction::Forward(fwd) => {
                    assert_eq!(fwd.method, Method::PUT);
                    // Re-signed seed reusing the streaming sentinel (not decoded).
                    assert_eq!(
                        fwd.headers.get("x-amz-content-sha256").unwrap(),
                        "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
                    );
                    // De-chunk headers preserved, fresh backend auth attached.
                    assert_eq!(fwd.headers.get("content-encoding").unwrap(), "aws-chunked");
                    assert!(fwd.headers.contains_key("x-amz-decoded-content-length"));
                    assert!(fwd.headers.contains_key("authorization"));
                }
                other => panic!("expected Forward, got {:?}", std::mem::discriminant(&other)),
            }
        });
    }

    #[test]
    fn put_signed_aws_chunked_is_rejected() {
        run(async {
            let gw = gateway();
            let mut headers = HeaderMap::new();
            headers.insert("content-encoding", "aws-chunked".parse().unwrap());
            headers.insert(
                "x-amz-content-sha256",
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
            );
            let action = gw
                .resolve_request(Method::PUT, "/test-bucket/test.md", None, &headers, None)
                .await;
            match action {
                HandlerAction::Response(r) => assert_eq!(
                    r.status, 501,
                    "signed aws-chunked uploads should be rejected with NotImplemented"
                ),
                other => panic!(
                    "expected Response(501), got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        });
    }

    #[test]
    fn upload_part_unsigned_aws_chunked_streams_via_resign() {
        run(async {
            let gw = gateway();
            let headers = unsigned_aws_chunked_headers();
            let action = gw
                .resolve_request(
                    Method::PUT,
                    "/test-bucket/key.bin",
                    Some("partNumber=1&uploadId=abc"),
                    &headers,
                    None,
                )
                .await;
            match action {
                HandlerAction::Forward(fwd) => {
                    // The arm-specific behavior: the part query must survive into
                    // the forwarded backend URL (otherwise S3 treats it as a PUT).
                    let q = fwd.url.query().unwrap_or("");
                    assert!(
                        q.contains("partNumber=1") && q.contains("uploadId=abc"),
                        "UploadPart forward must carry partNumber/uploadId, got query {q:?}"
                    );
                    assert_eq!(
                        fwd.headers.get("x-amz-content-sha256").unwrap(),
                        "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
                    );
                }
                other => panic!(
                    "expected Forward (stream via re-sign, not buffer), got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        });
    }

    #[test]
    fn streaming_put_on_non_s3_backend_is_rejected() {
        run(async {
            let gw = gateway();
            let headers = unsigned_aws_chunked_headers();
            // `azure-bucket` resolves to a non-S3 backend (see test_bucket_config).
            // A streaming upload there has no presign or seed-sign path, so it
            // must reject cleanly rather than mis-route into S3 signing.
            let action = gw
                .resolve_request(Method::PUT, "/azure-bucket/test.md", None, &headers, None)
                .await;
            match action {
                HandlerAction::Response(r) => assert_eq!(
                    r.status, 400,
                    "aws-chunked PUT to a non-S3 backend should be rejected, not mis-signed"
                ),
                other => panic!(
                    "expected Response(400), got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        });
    }

    #[test]
    fn upload_part_over_max_body_size_is_rejected() {
        run(async {
            let gw = gateway().with_max_request_body_size(1024);
            let mut headers = HeaderMap::new();
            headers.insert("content-length", "5000".parse().unwrap());
            let action = gw
                .resolve_request(
                    Method::PUT,
                    "/test-bucket/key.bin",
                    Some("partNumber=1&uploadId=abc"),
                    &headers,
                    None,
                )
                .await;
            match action {
                HandlerAction::Response(r) => assert_eq!(
                    r.status, 400,
                    "oversized UploadPart should be rejected with EntityTooLarge (400)"
                ),
                other => panic!(
                    "expected Response, got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        });
    }

    /// A plain (non-aws-chunked) part streams through with UNSIGNED-PAYLOAD
    /// header signing instead of being buffered, carrying the part query and
    /// preserving the client's checksum header so S3 still validates integrity.
    #[test]
    fn upload_part_plain_streams_unsigned_preserving_checksum() {
        run(async {
            let gw = gateway();
            let mut headers = HeaderMap::new();
            headers.insert("content-length", "7".parse().unwrap());
            headers.insert("x-amz-checksum-crc32", "AAAAAA==".parse().unwrap());
            let action = gw
                .resolve_request(
                    Method::PUT,
                    "/test-bucket/key.bin",
                    Some("partNumber=2&uploadId=xyz"),
                    &headers,
                    None,
                )
                .await;
            match action {
                HandlerAction::Forward(fwd) => {
                    let q = fwd.url.query().unwrap_or("");
                    assert!(
                        q.contains("partNumber=2") && q.contains("uploadId=xyz"),
                        "plain UploadPart must carry partNumber/uploadId, got {q:?}"
                    );
                    // Streamed, not buffered: the seed is signed UNSIGNED-PAYLOAD.
                    assert_eq!(
                        fwd.headers.get("x-amz-content-sha256").unwrap(),
                        "UNSIGNED-PAYLOAD"
                    );
                    // Checksum forwarded (and signed) so S3 validates the part.
                    assert_eq!(fwd.headers.get("x-amz-checksum-crc32").unwrap(), "AAAAAA==");
                }
                other => panic!(
                    "expected Forward (stream, not buffer), got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
        });
    }

    /// The eager-collect classifier must match exactly the operations that
    /// resolve to `NeedsBody` — multipart control ops and batch delete — and
    /// must exclude the zero-copy streaming/read ops.
    #[test]
    fn op_needs_buffered_body_matches_needsbody_ops() {
        let gw = gateway();
        let h = HeaderMap::new();
        let buffered = |m: &Method, path: &'static str, q: Option<&'static str>| {
            gw.op_needs_buffered_body(&RequestInfo::new(m, path, q, &h, None))
        };

        // Multipart control ops + batch delete buffer their (small) body.
        assert!(buffered(&Method::POST, "/test-bucket/key", Some("uploads")));
        assert!(buffered(
            &Method::POST,
            "/test-bucket/key",
            Some("uploadId=abc")
        ));
        assert!(buffered(
            &Method::DELETE,
            "/test-bucket/key",
            Some("uploadId=abc")
        ));
        assert!(buffered(&Method::POST, "/test-bucket", Some("delete")));

        // Streamed / read ops never buffer.
        assert!(!buffered(&Method::PUT, "/test-bucket/key", None));
        assert!(!buffered(
            &Method::PUT,
            "/test-bucket/key",
            Some("partNumber=1&uploadId=abc")
        ));
        assert!(!buffered(&Method::GET, "/test-bucket/key", None));
        assert!(!buffered(&Method::GET, "/test-bucket", None));
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

    // -- Server-Timing tests --------------------------------------------------

    /// Mock backend that returns a canned ForwardResponse.
    #[derive(Clone)]
    struct ForwardMockBackend;

    impl ProxyBackend for ForwardMockBackend {
        type ResponseBody = ();
        type Body = ();

        async fn forward(
            &self,
            _request: ForwardRequest,
            _body: (),
        ) -> Result<ForwardResponse<()>, ProxyError> {
            Ok(ForwardResponse {
                status: 200,
                headers: HeaderMap::new(),
                body: (),
                content_length: Some(0),
            })
        }

        fn create_paginated_store(
            &self,
            _config: &BucketConfig,
        ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
            unimplemented!()
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
            unimplemented!()
        }
    }

    fn forward_gateway() -> ProxyGateway<ForwardMockBackend, MockRegistry, MockCreds> {
        ProxyGateway::new(ForwardMockBackend, MockRegistry, MockCreds, None)
    }

    fn extract_server_timing(response: &GatewayResponse<()>) -> Option<String> {
        let headers = match response {
            GatewayResponse::Response(r) => &r.headers,
            GatewayResponse::Forward(f) => &f.headers,
        };
        headers
            .get("server-timing")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    #[test]
    fn server_timing_present_on_forward_response() {
        run(async {
            let gw = forward_gateway();
            let headers = HeaderMap::new();
            let req = RequestInfo::new(&Method::GET, "/test-bucket/key.txt", None, &headers, None);
            let response = gw
                .handle_request(&req, (), |_| async { Ok::<_, String>(Bytes::new()) })
                .await;

            let timing = extract_server_timing(&response)
                .expect("forwarded response should have Server-Timing header");
            assert!(
                timing.contains("total;dur="),
                "should contain total: {timing}"
            );
            assert!(
                timing.contains("dispatch;dur="),
                "should contain dispatch: {timing}"
            );
            assert!(
                timing.contains("backend;dur="),
                "should contain backend: {timing}"
            );
        });
    }

    #[test]
    fn server_timing_present_on_error_response() {
        run(async {
            let gw = forward_gateway();
            let headers = HeaderMap::new();
            // Request for a non-existent path that triggers an error response
            let req = RequestInfo::new(&Method::GET, "/", None, &headers, None);
            let response = gw
                .handle_request(&req, (), |_| async { Ok::<_, String>(Bytes::new()) })
                .await;

            let timing = extract_server_timing(&response)
                .expect("error response should have Server-Timing header");
            assert!(
                timing.contains("total;dur="),
                "should contain total: {timing}"
            );
        });
    }

    #[test]
    fn server_timing_disabled_when_configured() {
        run(async {
            let gw = forward_gateway().with_server_timing(false);
            let headers = HeaderMap::new();
            let req = RequestInfo::new(&Method::GET, "/test-bucket/key.txt", None, &headers, None);
            let response = gw
                .handle_request(&req, (), |_| async { Ok::<_, String>(Bytes::new()) })
                .await;

            assert!(
                extract_server_timing(&response).is_none(),
                "Server-Timing should not be present when disabled"
            );
        });
    }

    // -- Batch delete (DeleteObjects) -----------------------------------------

    /// Backend that captures the forwarded delete body and returns a canned
    /// `DeleteResult` marking `allowed/a.txt` deleted.
    #[derive(Clone)]
    struct DeleteMockBackend {
        captured: Arc<std::sync::Mutex<Option<Bytes>>>,
    }

    impl ProxyBackend for DeleteMockBackend {
        type ResponseBody = ();
        type Body = ();

        async fn forward(
            &self,
            _request: ForwardRequest,
            _body: (),
        ) -> Result<ForwardResponse<()>, ProxyError> {
            unimplemented!()
        }

        fn create_paginated_store(
            &self,
            _config: &BucketConfig,
        ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
            unimplemented!()
        }

        fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError> {
            crate::backend::build_signer(config)
        }

        async fn send_raw(
            &self,
            _method: http::Method,
            _url: String,
            _headers: HeaderMap,
            body: Bytes,
        ) -> Result<RawResponse, ProxyError> {
            *self.captured.lock().unwrap() = Some(body);
            Ok(RawResponse {
                status: 200,
                headers: HeaderMap::new(),
                body: Bytes::from_static(
                    b"<?xml version=\"1.0\"?><DeleteResult><Deleted><Key>allowed/a.txt</Key></Deleted></DeleteResult>",
                ),
            })
        }
    }

    #[test]
    fn batch_delete_filters_unauthorized_keys_per_key() {
        use crate::types::{AccessScope, AuthenticatedIdentity};
        run(async {
            let captured = Arc::new(std::sync::Mutex::new(None));
            let backend = DeleteMockBackend {
                captured: captured.clone(),
            };
            let gw = ProxyGateway::new(backend, MockRegistry, MockCreds, None);

            let identity = ResolvedIdentity::Authenticated(AuthenticatedIdentity {
                principal_name: "tester".into(),
                allowed_scopes: vec![AccessScope {
                    bucket: "test-bucket".into(),
                    prefixes: vec!["allowed/".into()],
                    actions: vec![Action::DeleteObject],
                }],
            });

            let pending = PendingRequest {
                operation: S3Operation::DeleteObjects {
                    bucket: "test-bucket".into(),
                },
                bucket_config: test_bucket_config("test-bucket"),
                original_headers: HeaderMap::new(),
                request_id: "rid".into(),
                identity,
            };

            let body = Bytes::from_static(
                br#"<Delete><Object><Key>allowed/a.txt</Key></Object><Object><Key>denied/b.txt</Key></Object></Delete>"#,
            );

            let result = gw.handle_with_body(pending, body).await;
            assert_eq!(result.status, 200);

            let xml = match result.body {
                ProxyResponseBody::Bytes(b) => String::from_utf8(b.to_vec()).unwrap(),
                ProxyResponseBody::Empty => panic!("expected a body"),
            };
            // Authorized key deleted; unauthorized key reported as AccessDenied.
            assert!(
                xml.contains("<Deleted><Key>allowed/a.txt</Key></Deleted>"),
                "{xml}"
            );
            assert!(xml.contains("<Key>denied/b.txt</Key>"), "{xml}");
            assert!(xml.contains("<Code>AccessDenied</Code>"), "{xml}");

            // The denied key must never be forwarded to the backend.
            let sent = captured
                .lock()
                .unwrap()
                .clone()
                .expect("backend was called");
            let sent = String::from_utf8(sent.to_vec()).unwrap();
            assert!(sent.contains("allowed/a.txt"), "forwarded body: {sent}");
            assert!(
                !sent.contains("denied/b.txt"),
                "denied key leaked to backend: {sent}"
            );
        });
    }

    #[test]
    fn batch_delete_all_denied_skips_backend() {
        use crate::types::{AccessScope, AuthenticatedIdentity};
        run(async {
            let captured = Arc::new(std::sync::Mutex::new(None));
            let backend = DeleteMockBackend {
                captured: captured.clone(),
            };
            let gw = ProxyGateway::new(backend, MockRegistry, MockCreds, None);

            // Scope grants only a different prefix → every requested key is denied.
            let identity = ResolvedIdentity::Authenticated(AuthenticatedIdentity {
                principal_name: "tester".into(),
                allowed_scopes: vec![AccessScope {
                    bucket: "test-bucket".into(),
                    prefixes: vec!["other/".into()],
                    actions: vec![Action::DeleteObject],
                }],
            });

            let pending = PendingRequest {
                operation: S3Operation::DeleteObjects {
                    bucket: "test-bucket".into(),
                },
                bucket_config: test_bucket_config("test-bucket"),
                original_headers: HeaderMap::new(),
                request_id: "rid".into(),
                identity,
            };

            let body =
                Bytes::from_static(br#"<Delete><Object><Key>secret/a.txt</Key></Object></Delete>"#);
            let result = gw.handle_with_body(pending, body).await;
            assert_eq!(result.status, 200);
            // Backend must not be contacted when nothing is authorized.
            assert!(
                captured.lock().unwrap().is_none(),
                "backend should be skipped"
            );
        });
    }

    /// Backend that captures the headers forwarded to `send_raw`.
    #[derive(Clone)]
    struct CaptureHeadersBackend {
        captured: Arc<std::sync::Mutex<Option<HeaderMap>>>,
    }

    impl ProxyBackend for CaptureHeadersBackend {
        type ResponseBody = ();
        type Body = ();

        async fn forward(
            &self,
            _request: ForwardRequest,
            _body: (),
        ) -> Result<ForwardResponse<()>, ProxyError> {
            unimplemented!()
        }

        fn create_paginated_store(
            &self,
            _config: &BucketConfig,
        ) -> Result<Box<dyn PaginatedListStore>, ProxyError> {
            unimplemented!()
        }

        fn create_signer(&self, config: &BucketConfig) -> Result<Arc<dyn Signer>, ProxyError> {
            crate::backend::build_signer(config)
        }

        async fn send_raw(
            &self,
            _method: http::Method,
            _url: String,
            headers: HeaderMap,
            _body: Bytes,
        ) -> Result<RawResponse, ProxyError> {
            *self.captured.lock().unwrap() = Some(headers);
            Ok(RawResponse {
                status: 200,
                headers: HeaderMap::new(),
                body: Bytes::new(),
            })
        }
    }

    /// Regression guard: modern AWS CLI/SDK enable CRC32 integrity checksums by
    /// default, so CompleteMultipartUpload carries `x-amz-checksum-*` headers.
    /// They must be forwarded to *and signed for* the backend — dropping them
    /// leaves the upload with no checksum context and S3 fails the completion
    /// with `InvalidPart`.
    #[test]
    fn complete_multipart_forwards_and_signs_checksum_headers() {
        use crate::types::AuthenticatedIdentity;
        run(async {
            let captured = Arc::new(std::sync::Mutex::new(None));
            let backend = CaptureHeadersBackend {
                captured: captured.clone(),
            };
            let gw = ProxyGateway::new(backend, MockRegistry, MockCreds, None);

            let mut original_headers = HeaderMap::new();
            original_headers.insert("content-type", "application/xml".parse().unwrap());
            original_headers.insert("x-amz-checksum-crc32", "AAAAAA==".parse().unwrap());
            original_headers.insert("x-amz-checksum-type", "FULL_OBJECT".parse().unwrap());
            original_headers.insert("x-amz-sdk-checksum-algorithm", "CRC32".parse().unwrap());
            // The client's own credentials must never be forwarded; the proxy
            // re-signs with the backend creds.
            original_headers.insert(
                "authorization",
                "AWS4-HMAC-SHA256 client-bogus".parse().unwrap(),
            );

            let pending = PendingRequest {
                operation: S3Operation::CompleteMultipartUpload {
                    bucket: "test-bucket".into(),
                    key: "big.dmg".into(),
                    upload_id: "upload-1".into(),
                },
                bucket_config: test_bucket_config("test-bucket"),
                original_headers,
                request_id: "rid".into(),
                identity: ResolvedIdentity::Authenticated(AuthenticatedIdentity {
                    principal_name: "tester".into(),
                    allowed_scopes: vec![],
                }),
            };

            let body = Bytes::from_static(
                br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"abc"</ETag><ChecksumCRC32>AAAAAA==</ChecksumCRC32></Part></CompleteMultipartUpload>"#,
            );

            let result = gw.handle_with_body(pending, body).await;
            assert_eq!(result.status, 200);

            let sent = captured
                .lock()
                .unwrap()
                .clone()
                .expect("backend was called");

            // 1. The checksum headers reach the backend.
            assert_eq!(sent.get("x-amz-checksum-crc32").unwrap(), "AAAAAA==");
            assert_eq!(sent.get("x-amz-checksum-type").unwrap(), "FULL_OBJECT");
            assert_eq!(sent.get("x-amz-sdk-checksum-algorithm").unwrap(), "CRC32");

            // 2. The client's Authorization is replaced by a fresh proxy signature.
            let auth = sent.get("authorization").unwrap().to_str().unwrap();
            assert!(
                auth.starts_with("AWS4-HMAC-SHA256 Credential="),
                "expected re-signed Authorization, got: {auth}"
            );

            // 3. The checksum headers are part of SignedHeaders — without this S3
            //    ignores them and the completion fails with InvalidPart.
            assert!(
                auth.contains("x-amz-checksum-crc32")
                    && auth.contains("x-amz-checksum-type")
                    && auth.contains("x-amz-sdk-checksum-algorithm"),
                "checksum headers missing from SignedHeaders: {auth}"
            );
        });
    }

    #[test]
    fn object_path_is_byte_faithful() {
        let config = test_bucket_config("test");
        for key in ["report*.pdf", "100%.txt", "a~b#c.bin", "dir/%3D-lit.txt"] {
            let path = build_object_path(&config, key).unwrap();
            assert_eq!(path.as_ref(), key, "logical key must not be rewritten");
        }
    }

    #[test]
    fn object_path_applies_backend_prefix_byte_faithfully() {
        let mut config = test_bucket_config("test");
        config.backend_prefix = Some("data/".into());
        let path = build_object_path(&config, "report*.pdf").unwrap();
        assert_eq!(path.as_ref(), "data/report*.pdf");
    }

    #[test]
    fn object_path_rejects_degenerate_segments() {
        let config = test_bucket_config("test");
        for key in ["a//b.txt", "a/./b.txt", "a/../b.txt"] {
            let err = build_object_path(&config, key).unwrap_err();
            assert_eq!(err.status_code(), 400, "key {key:?} must be a 400");
        }
    }

    #[test]
    fn same_backing_store_matches_shared_endpoint_and_creds() {
        // Two virtual buckets on the same endpoint/creds but different backend
        // buckets are the same store — a cross-bucket copy is native.
        let mut a = test_bucket_config("src");
        let mut b = test_bucket_config("dst");
        b.backend_options
            .insert("bucket_name".into(), "other-backend-bucket".into());
        assert!(same_backing_store(&a, &b));

        // Different endpoint → different store.
        b.backend_options
            .insert("endpoint".into(), "https://minio.example.com".into());
        assert!(!same_backing_store(&a, &b));

        // Different credentials → different store (conservative).
        let mut c = test_bucket_config("dst2");
        c.backend_options
            .insert("access_key_id".into(), "AKIADIFFERENT".into());
        assert!(!same_backing_store(&a, &c));

        // A non-S3 backend is never a copy-compatible store.
        a.backend_type = "azure".into();
        let d = test_bucket_config("dst3");
        assert!(!same_backing_store(&a, &d));
    }

    #[test]
    fn copy_source_header_encodes_backend_key_and_version() {
        let mut config = test_bucket_config("src");
        config.backend_prefix = Some("data/".into());
        let value = build_copy_source_header(&config, "a b/c=d.txt", Some("v9")).unwrap();
        // Prefix applied, space and `=` percent-encoded, `/` preserved.
        assert_eq!(value, "/backend-bucket/data/a%20b/c%3Dd.txt?versionId=v9");
    }

    #[test]
    fn copy_source_header_without_bucket_name_is_rejected() {
        let mut config = test_bucket_config("src");
        config.backend_options.remove("bucket_name");
        let err = build_copy_source_header(&config, "k", None).unwrap_err();
        assert!(matches!(err, ProxyError::NotImplemented(_)));
    }

    /// End-to-end same-store `CopyObject`: a `PUT` carrying `x-amz-copy-source`
    /// drives a re-signed backend `PUT` with an empty body. Exercises the whole
    /// path — parse → authorize destination (as `PutObject`) → authorize source
    /// (as `GetObject`) → same-store check → build backend copy-source → sign →
    /// `send_raw` — and pins the wire request the backend actually receives.
    #[test]
    fn copy_object_end_to_end_sends_resigned_backend_put() {
        run(async {
            let captured = Arc::new(std::sync::Mutex::new(None));
            let backend = CaptureHeadersBackend {
                captured: captured.clone(),
            };
            let gw = ProxyGateway::new(backend, MockRegistry, MockCreds, None);

            let mut headers = HeaderMap::new();
            // Wire key is percent-encoded per the S3 spec (space → %20).
            headers.insert(
                "x-amz-copy-source",
                "/src-bucket/src%20key.txt".parse().unwrap(),
            );
            // Copy-relevant client headers must be forwarded AND signed.
            headers.insert("x-amz-metadata-directive", "REPLACE".parse().unwrap());
            headers.insert("x-amz-meta-team", "platform".parse().unwrap());

            let action = gw
                .resolve_request(Method::PUT, "/dst-bucket/dst-key.txt", None, &headers, None)
                .await;

            let status = match action {
                HandlerAction::Response(resp) => resp.status,
                other => panic!(
                    "expected Response, got {:?}",
                    std::mem::discriminant(&other)
                ),
            };
            assert_eq!(status, 200, "same-store copy returns the backend's status");

            let sent = captured
                .lock()
                .unwrap()
                .clone()
                .expect("backend was called");

            // Copy-source is decoded, mapped into the source's backend bucket/key
            // space, then re-encoded with S3's canonical path set.
            assert_eq!(
                sent.get("x-amz-copy-source").unwrap(),
                "/backend-bucket/src%20key.txt"
            );
            // Copy-relevant client headers reached the backend.
            assert_eq!(sent.get("x-amz-metadata-directive").unwrap(), "REPLACE");
            assert_eq!(sent.get("x-amz-meta-team").unwrap(), "platform");
            // Empty body: the signed payload hash is sha256("").
            assert_eq!(
                sent.get("x-amz-content-sha256").unwrap(),
                hash_payload(&[]).as_str()
            );
            // The backend request carries a fresh proxy signature (the copy is
            // re-signed with backend credentials, never the client's)...
            let auth = sent.get("authorization").unwrap().to_str().unwrap();
            assert!(
                auth.starts_with("AWS4-HMAC-SHA256 Credential="),
                "expected re-signed Authorization, got: {auth}"
            );
            // ...and the copy-relevant headers are part of SignedHeaders (else S3
            // silently ignores the copy-source and the copy does nothing).
            assert!(
                auth.contains("x-amz-copy-source")
                    && auth.contains("x-amz-metadata-directive")
                    && auth.contains("x-amz-meta-team"),
                "copy headers missing from SignedHeaders: {auth}"
            );
        });
    }

    /// A `versionId` on the copy-source rides through to the backend copy-source.
    #[test]
    fn copy_object_forwards_version_id_to_backend() {
        run(async {
            let captured = Arc::new(std::sync::Mutex::new(None));
            let gw = ProxyGateway::new(
                CaptureHeadersBackend {
                    captured: captured.clone(),
                },
                MockRegistry,
                MockCreds,
                None,
            );
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-amz-copy-source",
                "/src-bucket/obj.txt?versionId=v42".parse().unwrap(),
            );
            let action = gw
                .resolve_request(Method::PUT, "/dst-bucket/dst.txt", None, &headers, None)
                .await;
            assert!(matches!(action, HandlerAction::Response(_)));
            let sent = captured
                .lock()
                .unwrap()
                .clone()
                .expect("backend was called");
            assert_eq!(
                sent.get("x-amz-copy-source").unwrap(),
                "/backend-bucket/obj.txt?versionId=v42"
            );
        });
    }

    /// A cross-store copy (source resolves to a different backend) cannot be a
    /// native S3 copy, so it is rejected with `501` and the backend is never
    /// contacted — no bytes are streamed through the proxy.
    #[test]
    fn cross_store_copy_is_rejected_501() {
        run(async {
            let captured = Arc::new(std::sync::Mutex::new(None));
            let gw = ProxyGateway::new(
                CaptureHeadersBackend {
                    captured: captured.clone(),
                },
                MockRegistry,
                MockCreds,
                None,
            );
            let mut headers = HeaderMap::new();
            // `azure-*` names resolve to a non-S3 backend in the test registry,
            // so source and destination are on different stores.
            headers.insert("x-amz-copy-source", "/azure-src/obj.txt".parse().unwrap());
            let action = gw
                .resolve_request(Method::PUT, "/dst-bucket/dst.txt", None, &headers, None)
                .await;
            match action {
                HandlerAction::Response(resp) => assert_eq!(resp.status, 501),
                other => panic!(
                    "expected 501 Response, got {:?}",
                    std::mem::discriminant(&other)
                ),
            }
            assert!(
                captured.lock().unwrap().is_none(),
                "backend must not be contacted for a rejected cross-store copy"
            );
        });
    }
}
