//! Unit tests for [`ProxyGateway`](super::ProxyGateway).

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
        crate::types::BackendType::Azure
    } else {
        crate::types::BackendType::S3
    };
    BucketConfig {
        name: name.to_string(),
        backend_type,
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

#[test]
fn put_forward_preserves_conditional_headers() {
    run(async {
        let gw = gateway();
        let mut headers = HeaderMap::new();
        headers.insert("if-match", "\"abc123\"".parse().unwrap());
        headers.insert("if-none-match", "*".parse().unwrap());
        let action = gw
            .resolve_request(Method::PUT, "/test-bucket/key.txt", None, &headers, None)
            .await;

        match action {
            HandlerAction::Forward(fwd) => {
                assert_eq!(fwd.method, Method::PUT);
                assert_eq!(
                    fwd.headers.get("if-match").map(|v| v.to_str().unwrap()),
                    Some("\"abc123\""),
                    "PUT forward should pass through If-Match so the backend enforces the precondition (412)"
                );
                assert_eq!(
                    fwd.headers
                        .get("if-none-match")
                        .map(|v| v.to_str().unwrap()),
                    Some("*"),
                    "PUT forward should pass through If-None-Match"
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
fn invalid_user_agent_is_rejected_at_configuration() {
    // A newline is not a valid header value. It must be rejected when the
    // gateway is configured, not panic on the first forwarded request.
    assert!(gateway().with_user_agent("bad\nagent").is_err());
}

#[test]
fn custom_user_agent_is_used_in_forward() {
    run(async {
        let gw = gateway()
            .with_user_agent("myapp/1.0 multistore/0.2.0")
            .expect("valid user agent");
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
fn same_s3_endpoint_matches_shared_endpoint_and_region() {
    // Two virtual buckets on the same endpoint but different backend
    // buckets are copy-compatible — a cross-bucket copy is native.
    let mut a = test_bucket_config("src");
    let mut b = test_bucket_config("dst");
    b.backend_options
        .insert("bucket_name".into(), "other-backend-bucket".into());
    assert!(same_s3_endpoint(&a, &b));

    // Different endpoint → a copy can't reach across.
    b.backend_options
        .insert("endpoint".into(), "https://minio.example.com".into());
    assert!(!same_s3_endpoint(&a, &b));

    // Different region → likewise.
    let mut c = test_bucket_config("dst2");
    c.backend_options
        .insert("region".into(), "eu-west-1".into());
    assert!(!same_s3_endpoint(&a, &c));

    // A non-S3 backend is never a copy-compatible store.
    a.backend_type = crate::types::BackendType::Azure;
    let d = test_bucket_config("dst3");
    assert!(!same_s3_endpoint(&a, &d));
}

/// A credential-injecting middleware (`AwsBackendAuth`) resolves
/// `auth_type=oidc` into minted STS keys, but only on the *destination*
/// config in the dispatch context — the copy source is resolved afterwards
/// and still carries its unresolved form. Comparing credentials therefore
/// rejected every copy on such a deployment; the endpoint is what matters.
#[test]
fn middleware_resolved_destination_still_matches_unresolved_source() {
    let mut src = test_bucket_config("src");
    src.backend_options.remove("access_key_id");
    src.backend_options.remove("secret_access_key");
    src.backend_options
        .insert("auth_type".into(), "oidc".into());
    src.backend_options.insert(
        "oidc_role_arn".into(),
        "arn:aws:iam::123:role/Reader".into(),
    );

    // Post-middleware destination: `auth_type` swapped for minted keys.
    let mut dst = test_bucket_config("dst");
    dst.backend_options
        .insert("access_key_id".into(), "ASIAMINTEDBYSTS".into());
    dst.backend_options
        .insert("secret_access_key".into(), "minted-secret".into());
    dst.backend_options
        .insert("token".into(), "sts-session-token".into());

    assert!(same_s3_endpoint(&src, &dst));
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

/// A registry that only knows internal, already-mapped bucket names — the
/// shape a path-mapping proxy presents (`/{account}/{product}/{key}` is
/// rewritten to the bucket `account:product` before dispatch).
#[derive(Clone)]
struct MappedMockRegistry;

impl BucketRegistry for MappedMockRegistry {
    async fn get_bucket(
        &self,
        name: &str,
        _identity: &ResolvedIdentity,
        _operation: &S3Operation,
    ) -> Result<ResolvedBucket, ProxyError> {
        if !name.contains(':') {
            return Err(ProxyError::BucketNotFound(name.to_string()));
        }
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

/// `x-amz-copy-source` carries a *client-facing* path, which the URL
/// rewrite never touches. Without a mapped override the gateway resolves
/// the raw first segment (an account, not a bucket) and the copy dies with
/// `NoSuchBucket` — the failure every SDK client hits, since they all send
/// the client-facing form.
#[test]
fn unmapped_copy_source_fails_on_a_path_mapping_registry() {
    run(async {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: captured.clone(),
            },
            MappedMockRegistry,
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            "/account/product/README.md".parse().unwrap(),
        );
        let action = gw
            .resolve_request(
                Method::PUT,
                "/account:product/README.md.copy",
                None,
                &headers,
                None,
            )
            .await;
        match action {
            HandlerAction::Response(resp) => assert_eq!(resp.status, 404),
            other => panic!(
                "expected 404 Response, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert!(captured.lock().unwrap().is_none());
    });
}

/// The same request succeeds once the proxy supplies the copy-source
/// mapped into the gateway's bucket namespace. The signed header is left
/// alone; only source resolution uses the override.
#[test]
fn mapped_copy_source_override_resolves_the_source() {
    run(async {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: captured.clone(),
            },
            MappedMockRegistry,
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            "/account/product/README.md".parse().unwrap(),
        );
        let method = Method::PUT;
        let req = RequestInfo::new(
            &method,
            "/account:product/README.md.copy",
            None,
            &headers,
            None,
        )
        .with_copy_source(Some("/account:product/README.md"));

        let (action, _) = gw.resolve_request_with_metadata(&req).await;
        match action {
            HandlerAction::Response(resp) => assert_eq!(resp.status, 200),
            other => panic!(
                "expected 200 Response, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        let sent = captured
            .lock()
            .unwrap()
            .clone()
            .expect("backend was called");
        assert_eq!(
            sent.get("x-amz-copy-source").unwrap(),
            "/backend-bucket/README.md"
        );
    });
}

/// A registry whose configs carry `auth_type=oidc` — credentials are minted
/// by middleware, which only ever sees the destination config.
#[derive(Clone)]
struct OidcRegistry;

impl BucketRegistry for OidcRegistry {
    async fn get_bucket(
        &self,
        name: &str,
        _identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> Result<ResolvedBucket, ProxyError> {
        let mut config = test_bucket_config(name);
        // The destination has been through the credential middleware; the
        // copy source (resolved later, as a GetObject) has not.
        if matches!(operation, S3Operation::GetObject { .. }) {
            config.backend_options.remove("access_key_id");
            config.backend_options.remove("secret_access_key");
            config
                .backend_options
                .insert("auth_type".into(), "oidc".into());
        } else {
            config
                .backend_options
                .insert("token".into(), "sts-session-token".into());
        }
        Ok(ResolvedBucket {
            config,
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

/// Source and destination are the same product on the same endpoint, so the
/// copy is native — even though only the destination carries the STS
/// credentials the middleware minted.
#[test]
fn copy_succeeds_when_only_the_destination_has_minted_credentials() {
    run(async {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: captured.clone(),
            },
            OidcRegistry,
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-copy-source", "/src-bucket/obj.txt".parse().unwrap());
        let action = gw
            .resolve_request(
                Method::PUT,
                "/dst-bucket/obj.txt.copy",
                None,
                &headers,
                None,
            )
            .await;
        match action {
            HandlerAction::Response(resp) => assert_eq!(
                resp.status, 200,
                "asymmetric credential materialization must not read as a cross-store copy"
            ),
            other => panic!(
                "expected 200 Response, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert_eq!(
            captured
                .lock()
                .unwrap()
                .clone()
                .expect("backend was called")
                .get("x-amz-copy-source")
                .unwrap(),
            "/backend-bucket/obj.txt"
        );
    });
}

/// Records every authorization the gateway asks for, and optionally denies
/// one action so a half-authorized caller can be simulated.
#[derive(Clone)]
struct RecordingRegistry {
    seen: Arc<std::sync::Mutex<Vec<(String, Action, String)>>>,
    /// Versions seen on read authorizations, in order.
    versions: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    deny: Option<Action>,
    /// Deny any read that names an object version, standing in for a
    /// registry whose policy is not version-aware.
    deny_versioned_reads: bool,
}

impl BucketRegistry for RecordingRegistry {
    async fn get_bucket(
        &self,
        name: &str,
        _identity: &ResolvedIdentity,
        operation: &S3Operation,
    ) -> Result<ResolvedBucket, ProxyError> {
        self.seen.lock().unwrap().push((
            name.to_string(),
            operation.action(),
            operation.key().to_string(),
        ));
        if let S3Operation::GetObject { version, .. } = operation {
            self.versions.lock().unwrap().push(version.clone());
        }
        if self.deny == Some(operation.action()) {
            return Err(ProxyError::AccessDenied);
        }
        if self.deny_versioned_reads
            && matches!(
                operation,
                S3Operation::GetObject {
                    version: Some(_),
                    ..
                }
            )
        {
            return Err(ProxyError::AccessDenied);
        }
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

/// A copy is two permissions, not one. The registry — the authorization
/// seam — must be asked to authorize the destination as a write *and* the
/// source as a read, each against the key that end actually touches. A
/// registry that scopes by key prefix can only enforce that if the right
/// key reaches it.
#[test]
fn copy_authorizes_destination_write_and_source_read() {
    run(async {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: Arc::new(std::sync::Mutex::new(None)),
            },
            RecordingRegistry {
                seen: seen.clone(),
                versions: Arc::new(std::sync::Mutex::new(Vec::new())),
                deny: None,
                deny_versioned_reads: false,
            },
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            "/src-bucket/secret/obj.txt".parse().unwrap(),
        );
        let action = gw
            .resolve_request(
                Method::PUT,
                "/dst-bucket/public/obj.txt",
                None,
                &headers,
                None,
            )
            .await;
        assert!(matches!(action, HandlerAction::Response(_)));

        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                (
                    "dst-bucket".to_string(),
                    Action::PutObject,
                    "public/obj.txt".to_string()
                ),
                (
                    "src-bucket".to_string(),
                    Action::GetObject,
                    "secret/obj.txt".to_string()
                ),
            ],
            "a copy must authorize the destination write and the source read"
        );
    });
}

/// Write access to the destination is not enough: a caller who may not read
/// the source cannot launder it into a bucket they control. The denial
/// lands before the backend is contacted, so no bytes move.
#[test]
fn copy_denied_when_the_caller_cannot_read_the_source() {
    run(async {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: captured.clone(),
            },
            RecordingRegistry {
                seen: Arc::new(std::sync::Mutex::new(Vec::new())),
                versions: Arc::new(std::sync::Mutex::new(Vec::new())),
                deny: Some(Action::GetObject),
                deny_versioned_reads: false,
            },
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-copy-source", "/src-bucket/obj.txt".parse().unwrap());
        let action = gw
            .resolve_request(Method::PUT, "/dst-bucket/obj.txt", None, &headers, None)
            .await;
        match action {
            HandlerAction::Response(resp) => assert_eq!(resp.status, 403),
            other => panic!(
                "expected 403 Response, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert!(
            captured.lock().unwrap().is_none(),
            "an unauthorized source read must never reach the backend"
        );
    });
}

/// The mirror case: read access to the source does not let a caller write
/// the destination. Denied before the source is even resolved.
#[test]
fn copy_denied_when_the_caller_cannot_write_the_destination() {
    run(async {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: captured.clone(),
            },
            RecordingRegistry {
                seen: Arc::new(std::sync::Mutex::new(Vec::new())),
                versions: Arc::new(std::sync::Mutex::new(Vec::new())),
                deny: Some(Action::PutObject),
                deny_versioned_reads: false,
            },
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-copy-source", "/src-bucket/obj.txt".parse().unwrap());
        let action = gw
            .resolve_request(Method::PUT, "/dst-bucket/obj.txt", None, &headers, None)
            .await;
        match action {
            HandlerAction::Response(resp) => assert_eq!(resp.status, 403),
            other => panic!(
                "expected 403 Response, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert!(captured.lock().unwrap().is_none());
    });
}

/// A versioned copy-source reads bytes that no other operation can reach —
/// the read path ignores `?versionId=` and serves the current object. The
/// version must therefore reach the registry on the source authorization,
/// or a policy that would reject it never sees it.
#[test]
fn copy_source_version_reaches_the_source_authorization() {
    run(async {
        let versions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: Arc::new(std::sync::Mutex::new(None)),
            },
            RecordingRegistry {
                seen: Arc::new(std::sync::Mutex::new(Vec::new())),
                versions: versions.clone(),
                deny: None,
                deny_versioned_reads: false,
            },
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            "/src-bucket/obj.txt?versionId=v42".parse().unwrap(),
        );
        let action = gw
            .resolve_request(Method::PUT, "/dst-bucket/obj.txt", None, &headers, None)
            .await;
        assert!(matches!(action, HandlerAction::Response(_)));
        assert_eq!(
            versions.lock().unwrap().clone(),
            vec![Some("v42".to_string())],
            "the source read must be authorized against the version it copies"
        );
    });
}

/// An unversioned copy-source authorizes an unversioned read — the version
/// field describes the read that actually happens, not the request shape.
#[test]
fn unversioned_copy_source_authorizes_an_unversioned_read() {
    run(async {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: Arc::new(std::sync::Mutex::new(None)),
            },
            RecordingRegistry {
                seen: seen.clone(),
                versions: Arc::new(std::sync::Mutex::new(Vec::new())),
                deny: None,
                // Would reject a versioned read; this copy names no version.
                deny_versioned_reads: true,
            },
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-copy-source", "/src-bucket/obj.txt".parse().unwrap());
        let action = gw
            .resolve_request(Method::PUT, "/dst-bucket/obj.txt", None, &headers, None)
            .await;
        match action {
            HandlerAction::Response(resp) => assert_eq!(resp.status, 200),
            other => panic!(
                "expected 200 Response, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    });
}

/// A registry whose policy is not version-aware can now refuse the read,
/// and the refusal lands before the backend is contacted — no versioned
/// bytes move.
#[test]
fn registry_can_deny_a_versioned_copy_source() {
    run(async {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let gw = ProxyGateway::new(
            CaptureHeadersBackend {
                captured: captured.clone(),
            },
            RecordingRegistry {
                seen: Arc::new(std::sync::Mutex::new(Vec::new())),
                versions: Arc::new(std::sync::Mutex::new(Vec::new())),
                deny: None,
                deny_versioned_reads: true,
            },
            MockCreds,
            None,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            "/src-bucket/obj.txt?versionId=v42".parse().unwrap(),
        );
        let action = gw
            .resolve_request(Method::PUT, "/dst-bucket/obj.txt", None, &headers, None)
            .await;
        match action {
            HandlerAction::Response(resp) => assert_eq!(resp.status, 403),
            other => panic!(
                "expected 403 Response, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
        assert!(
            captured.lock().unwrap().is_none(),
            "a denied versioned read must never reach the backend"
        );
    });
}

/// A plain `GET` carrying `?versionId=` stays unversioned: the proxy does
/// not address versions on the read path, so authorizing it as versioned
/// would describe a read that never happens.
#[test]
fn plain_get_with_version_id_authorizes_an_unversioned_read() {
    let headers = HeaderMap::new();
    let op = crate::api::request::parse_s3_request(
        &Method::GET,
        "/b/obj.txt",
        Some("versionId=v42"),
        &headers,
        crate::api::request::HostStyle::Path,
        None,
    )
    .unwrap();
    assert!(
        matches!(op, S3Operation::GetObject { version: None, .. }),
        "expected an unversioned GetObject, got {op:?}"
    );
}
