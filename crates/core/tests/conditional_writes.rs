//! Integration test: conditional-write preconditions on `PutObject`.
//!
//! Drives the full [`ProxyGateway::handle_request`] pipeline (parse → authorize
//! → presign → forward → passthrough) against a backend that emulates S3's
//! conditional-write evaluation. Proves two things end-to-end:
//!
//! 1. `If-Match` / `If-None-Match` actually reach the backend on a `PutObject`
//!    (before the whitelist fix they were stripped, so the backend saw no
//!    precondition and every write "succeeded").
//! 2. The backend's `412 Precondition Failed` is surfaced to the client
//!    unchanged.

use bytes::Bytes;
use http::{HeaderMap, Method};
use std::collections::HashMap;
use std::sync::Arc;

use multistore::api::response::BucketEntry;
use multistore::backend::{build_signer, ForwardResponse, ProxyBackend, RawResponse};
use multistore::proxy::{GatewayResponse, ProxyGateway};
use multistore::registry::{BucketRegistry, CredentialRegistry, ResolvedBucket};
use multistore::route_handler::RequestInfo;
use multistore::types::{
    BucketConfig, ResolvedIdentity, RoleConfig, S3Operation, StoredCredential,
};
use object_store::list::PaginatedListStore;
use object_store::signer::Signer;

/// ETag of the object the fake backend pretends already exists.
const STORED_ETAG: &str = "\"v1\"";

/// Backend that emulates S3 compare-and-swap on the forwarded request headers.
///
/// The object with `STORED_ETAG` is assumed to exist. `forward` reads the
/// precondition headers off the presigned request and answers as S3 would:
/// `412` on a failed precondition, `200` otherwise.
#[derive(Clone)]
struct CasBackend;

impl ProxyBackend for CasBackend {
    type ResponseBody = ();
    type Body = ();

    async fn forward(
        &self,
        request: multistore::route_handler::ForwardRequest,
        _body: (),
    ) -> Result<ForwardResponse<()>, multistore::error::ProxyError> {
        let h = &request.headers;
        let precondition_failed = match (h.get("if-match"), h.get("if-none-match")) {
            // If-None-Match: * requires the object to be absent — it exists.
            (_, Some(v)) if v == "*" => true,
            // If-Match must equal the current ETag.
            (Some(v), _) => v.to_str().unwrap_or("") != STORED_ETAG,
            _ => false,
        };
        let status = if precondition_failed { 412 } else { 200 };
        Ok(ForwardResponse {
            status,
            headers: HeaderMap::new(),
            body: (),
            content_length: Some(0),
        })
    }

    fn create_paginated_store(
        &self,
        _config: &BucketConfig,
    ) -> Result<Box<dyn PaginatedListStore>, multistore::error::ProxyError> {
        unimplemented!("not exercised by conditional-write tests")
    }

    fn create_signer(
        &self,
        config: &BucketConfig,
    ) -> Result<Arc<dyn Signer>, multistore::error::ProxyError> {
        build_signer(config)
    }

    async fn send_raw(
        &self,
        _method: Method,
        _url: String,
        _headers: HeaderMap,
        _body: Bytes,
    ) -> Result<RawResponse, multistore::error::ProxyError> {
        unimplemented!("not exercised by conditional-write tests")
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
    ) -> Result<ResolvedBucket, multistore::error::ProxyError> {
        Ok(ResolvedBucket {
            config: test_bucket_config(name),
            list_rewrite: None,
            display_name: None,
        })
    }

    async fn list_buckets(
        &self,
        _identity: &ResolvedIdentity,
    ) -> Result<Vec<BucketEntry>, multistore::error::ProxyError> {
        Ok(vec![])
    }
}

#[derive(Clone)]
struct MockCreds;

impl CredentialRegistry for MockCreds {
    async fn get_credential(
        &self,
        _access_key_id: &str,
    ) -> Result<Option<StoredCredential>, multistore::error::ProxyError> {
        Ok(None)
    }

    async fn get_role(
        &self,
        _role_id: &str,
    ) -> Result<Option<RoleConfig>, multistore::error::ProxyError> {
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

/// PUT the object through the gateway with the given precondition headers and
/// return the status the client would see.
fn put_status(headers: HeaderMap) -> u16 {
    let gw = ProxyGateway::new(CasBackend, MockRegistry, MockCreds, None);
    let method = Method::PUT;
    let req = RequestInfo::new(&method, "/test-bucket/key.txt", None, &headers, None);
    let resp = run(gw.handle_request(&req, (), |b: ()| async move {
        let () = b;
        Ok::<Bytes, std::convert::Infallible>(Bytes::new())
    }));
    match resp {
        GatewayResponse::Response(r) => r.status,
        GatewayResponse::Forward(f) => f.status,
    }
}

#[test]
fn put_with_wrong_if_match_returns_412() {
    let mut headers = HeaderMap::new();
    headers.insert("if-match", "\"stale\"".parse().unwrap());
    assert_eq!(
        put_status(headers),
        412,
        "a PUT with a wrong If-Match must fail with 412 Precondition Failed, not silently succeed"
    );
}

#[test]
fn put_with_matching_if_match_succeeds() {
    let mut headers = HeaderMap::new();
    headers.insert("if-match", STORED_ETAG.parse().unwrap());
    assert_eq!(
        put_status(headers),
        200,
        "a PUT whose If-Match matches the current ETag must succeed"
    );
}

#[test]
fn put_with_if_none_match_star_fails_when_object_exists() {
    let mut headers = HeaderMap::new();
    headers.insert("if-none-match", "*".parse().unwrap());
    assert_eq!(
        put_status(headers),
        412,
        "If-None-Match: * must fail with 412 when the object already exists"
    );
}

#[test]
fn put_without_precondition_succeeds() {
    assert_eq!(
        put_status(HeaderMap::new()),
        200,
        "an unconditional PUT must succeed"
    );
}

/// AWS SDKs and the CLI send `PutObject` bodies as `aws-chunked` streaming
/// uploads, which take the header-signed streaming path rather than the
/// presigned one. The precondition must reach (and be enforced by) the backend
/// there too — otherwise the fix would miss the most common real-world client.
fn streaming_put_status(mut headers: HeaderMap) -> u16 {
    headers.insert(
        "x-amz-content-sha256",
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER".parse().unwrap(),
    );
    headers.insert("x-amz-decoded-content-length", "11".parse().unwrap());
    put_status(headers)
}

#[test]
fn streaming_put_with_wrong_if_match_returns_412() {
    let mut headers = HeaderMap::new();
    headers.insert("if-match", "\"stale\"".parse().unwrap());
    assert_eq!(
        streaming_put_status(headers),
        412,
        "an aws-chunked PUT with a wrong If-Match must fail with 412"
    );
}

#[test]
fn streaming_put_with_if_none_match_star_fails_when_object_exists() {
    let mut headers = HeaderMap::new();
    headers.insert("if-none-match", "*".parse().unwrap());
    assert_eq!(
        streaming_put_status(headers),
        412,
        "an aws-chunked If-None-Match: * must fail with 412 when the object exists"
    );
}

#[test]
fn streaming_put_with_matching_if_match_succeeds() {
    let mut headers = HeaderMap::new();
    headers.insert("if-match", STORED_ETAG.parse().unwrap());
    assert_eq!(
        streaming_put_status(headers),
        200,
        "an aws-chunked PUT whose If-Match matches must succeed"
    );
}
