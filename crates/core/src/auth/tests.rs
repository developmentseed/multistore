use super::*;
use crate::error::ProxyError;
use crate::types::{
    AccessScope, Action, BucketConfig, RoleConfig, StoredCredential, TemporaryCredentials,
};
use http::HeaderMap;
use sha2::{Digest, Sha256};

// ── Mock config provider ──────────────────────────────────────────

#[derive(Clone)]
struct MockConfig {
    credentials: Vec<StoredCredential>,
}

impl MockConfig {
    fn with_credential(secret: &str) -> Self {
        Self {
            credentials: vec![StoredCredential {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                secret_access_key: secret.into(),
                principal_name: "test-user".into(),
                allowed_scopes: vec![AccessScope {
                    bucket: "test-bucket".into(),
                    prefixes: vec![],
                    actions: vec![Action::GetObject],
                }],
                created_at: chrono::Utc::now(),
                expires_at: None,
                enabled: true,
            }],
        }
    }

    fn empty() -> Self {
        Self {
            credentials: vec![],
        }
    }
}

impl crate::config::ConfigProvider for MockConfig {
    async fn list_buckets(&self) -> Result<Vec<BucketConfig>, ProxyError> {
        Ok(vec![])
    }
    async fn get_bucket(&self, _: &str) -> Result<Option<BucketConfig>, ProxyError> {
        Ok(None)
    }
    async fn get_role(&self, _: &str) -> Result<Option<RoleConfig>, ProxyError> {
        Ok(None)
    }
    async fn get_credential(
        &self,
        access_key_id: &str,
    ) -> Result<Option<StoredCredential>, ProxyError> {
        Ok(self
            .credentials
            .iter()
            .find(|c| c.access_key_id == access_key_id)
            .cloned())
    }
}

// ── Test signing helper ───────────────────────────────────────────

/// Build a valid SigV4 Authorization header value for testing.
fn sign_request(
    method: &http::Method,
    uri_path: &str,
    query_string: &str,
    headers: &HeaderMap,
    access_key_id: &str,
    secret_access_key: &str,
    date_stamp: &str,
    amz_date: &str,
    region: &str,
    signed_header_names: &[&str],
    payload_hash: &str,
) -> String {
    let canonical_headers: String = signed_header_names
        .iter()
        .map(|name| {
            let value = headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .trim();
            format!("{}:{}\n", name, value)
        })
        .collect();

    let signed_headers_str = signed_header_names.join(";");

    // AWS SDKs sort query parameters when constructing the canonical request
    let canonical_query = sigv4::canonicalize_query_string(query_string);

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri_path, canonical_query, canonical_headers, signed_headers_str, payload_hash
    );

    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );

    let k_date = sigv4::hmac_sha256(
        format!("AWS4{}", secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    )
    .unwrap();
    let k_region = sigv4::hmac_sha256(&k_date, region.as_bytes()).unwrap();
    let k_service = sigv4::hmac_sha256(&k_region, b"s3").unwrap();
    let signing_key = sigv4::hmac_sha256(&k_service, b"aws4_request").unwrap();
    let signature =
        hex::encode(sigv4::hmac_sha256(&signing_key, string_to_sign.as_bytes()).unwrap());

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}/{}/s3/aws4_request, SignedHeaders={}, Signature={}",
        access_key_id, date_stamp, region, signed_headers_str, signature
    )
}

/// Build headers and auth for a simple GET request.
fn make_signed_headers(access_key_id: &str, secret_access_key: &str) -> HeaderMap {
    let date_stamp = "20240101";
    let amz_date = "20240101T000000Z";
    let region = "us-east-1";
    let payload_hash = "UNSIGNED-PAYLOAD";

    let mut headers = HeaderMap::new();
    headers.insert("host", "s3.example.com".parse().unwrap());
    headers.insert("x-amz-date", amz_date.parse().unwrap());
    headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());

    let auth = sign_request(
        &http::Method::GET,
        "/test-bucket/key.txt",
        "",
        &headers,
        access_key_id,
        secret_access_key,
        date_stamp,
        amz_date,
        region,
        &["host", "x-amz-content-sha256", "x-amz-date"],
        payload_hash,
    );
    headers.insert("authorization", auth.parse().unwrap());
    headers
}

// ── Tests ─────────────────────────────────────────────────────────

fn run<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}

#[test]
fn no_auth_header_returns_anonymous() {
    run(async {
        let headers = HeaderMap::new();
        let config = MockConfig::empty();

        let identity = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            None,
        )
        .await
        .unwrap();

        assert!(matches!(
            identity,
            crate::types::ResolvedIdentity::Anonymous
        ));
    });
}

#[test]
fn valid_signature_resolves_identity() {
    run(async {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let config = MockConfig::with_credential(secret);
        let headers = make_signed_headers("AKIAIOSFODNN7EXAMPLE", secret);

        let identity = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            None,
        )
        .await
        .unwrap();

        assert!(matches!(
            identity,
            crate::types::ResolvedIdentity::LongLived { .. }
        ));
    });
}

#[test]
fn valid_signature_with_unsorted_query_params() {
    run(async {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let config = MockConfig::with_credential(secret);

        let date_stamp = "20240101";
        let amz_date = "20240101T000000Z";
        let payload_hash = "UNSIGNED-PAYLOAD";

        let mut headers = HeaderMap::new();
        headers.insert("host", "s3.example.com".parse().unwrap());
        headers.insert("x-amz-date", amz_date.parse().unwrap());
        headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());

        // Sign with sorted query (as AWS SDKs do internally)
        let auth = sign_request(
            &http::Method::GET,
            "/test-bucket",
            "list-type=2&prefix=&delimiter=%2F&encoding-type=url",
            &headers,
            "AKIAIOSFODNN7EXAMPLE",
            secret,
            date_stamp,
            amz_date,
            "us-east-1",
            &["host", "x-amz-content-sha256", "x-amz-date"],
            payload_hash,
        );
        headers.insert("authorization", auth.parse().unwrap());

        // Pass UNSORTED query string (as it arrives from the raw URL)
        let identity = resolve_identity(
            &http::Method::GET,
            "/test-bucket",
            "list-type=2&prefix=&delimiter=%2F&encoding-type=url",
            &headers,
            &config,
            None,
        )
        .await
        .unwrap();

        assert!(matches!(
            identity,
            crate::types::ResolvedIdentity::LongLived { .. }
        ));
    });
}

#[test]
fn wrong_signature_is_rejected() {
    run(async {
        let real_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let wrong_secret = "WRONGSECRETKEYWRONGSECRETSECRET00000000000";
        let config = MockConfig::with_credential(real_secret);
        // Sign with wrong secret — access_key_id is correct, signature won't match
        let headers = make_signed_headers("AKIAIOSFODNN7EXAMPLE", wrong_secret);

        let err = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            None,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ProxyError::SignatureDoesNotMatch),
            "expected SignatureDoesNotMatch, got: {:?}",
            err
        );
    });
}

#[test]
fn garbage_signature_is_rejected() {
    run(async {
        let real_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let config = MockConfig::with_credential(real_secret);

        let mut headers = HeaderMap::new();
        headers.insert("host", "s3.example.com".parse().unwrap());
        headers.insert("x-amz-date", "20240101T000000Z".parse().unwrap());
        headers.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        headers.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240101/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
        );

        let err = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            None,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ProxyError::SignatureDoesNotMatch));
    });
}

#[test]
fn unknown_access_key_is_rejected() {
    run(async {
        let config = MockConfig::empty();
        let headers = make_signed_headers("AKIAUNKNOWN000000000", "some-secret");

        let err = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            None,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ProxyError::AccessDenied));
    });
}

#[test]
fn sealed_token_wrong_session_token_is_rejected() {
    use crate::sealed_token::TokenKey;

    run(async {
        let key_bytes = [0x42u8; 32];
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes);
        let token_key = TokenKey::from_base64(&encoded).unwrap();
        let config = MockConfig::empty();

        let secret = "TempSecretKey1234567890EXAMPLE000000000000";
        let wrong_token = "NOT_A_SEALED_TOKEN_AT_ALL";

        let date_stamp = "20240101";
        let amz_date = "20240101T000000Z";
        let payload_hash = "UNSIGNED-PAYLOAD";

        let mut headers = HeaderMap::new();
        headers.insert("host", "s3.example.com".parse().unwrap());
        headers.insert("x-amz-date", amz_date.parse().unwrap());
        headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());
        headers.insert("x-amz-security-token", wrong_token.parse().unwrap());

        let auth = sign_request(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            "ASIATEMP1234EXAMPLE",
            secret,
            date_stamp,
            amz_date,
            "us-east-1",
            &[
                "host",
                "x-amz-content-sha256",
                "x-amz-date",
                "x-amz-security-token",
            ],
            payload_hash,
        );
        headers.insert("authorization", auth.parse().unwrap());

        let err = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            Some(&token_key),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ProxyError::AccessDenied));
    });
}

#[test]
fn sealed_token_wrong_signature_is_rejected() {
    use crate::sealed_token::TokenKey;
    use crate::types::AccessScope;

    run(async {
        let key_bytes = [0x42u8; 32];
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes);
        let token_key = TokenKey::from_base64(&encoded).unwrap();

        let real_secret = "TempSecretKey1234567890EXAMPLE000000000000";
        let wrong_secret = "WRONGSECRETKEYWRONGSECRETSECRET00000000000";
        let creds = TemporaryCredentials {
            access_key_id: "ASIATEMP1234EXAMPLE".into(),
            secret_access_key: real_secret.into(),
            session_token: String::new(),
            expiration: chrono::Utc::now() + chrono::Duration::hours(1),
            allowed_scopes: vec![AccessScope {
                bucket: "test-bucket".into(),
                prefixes: vec![],
                actions: vec![Action::GetObject],
            }],
            assumed_role_id: "role-1".into(),
            source_identity: "test".into(),
        };

        let sealed = token_key.seal(&creds).unwrap();
        let config = MockConfig::empty();

        let date_stamp = "20240101";
        let amz_date = "20240101T000000Z";
        let payload_hash = "UNSIGNED-PAYLOAD";

        let mut headers = HeaderMap::new();
        headers.insert("host", "s3.example.com".parse().unwrap());
        headers.insert("x-amz-date", amz_date.parse().unwrap());
        headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());
        headers.insert("x-amz-security-token", sealed.parse().unwrap());

        // Sign with wrong secret — sealed token is valid but sig won't match
        let auth = sign_request(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            "ASIATEMP1234EXAMPLE",
            wrong_secret,
            date_stamp,
            amz_date,
            "us-east-1",
            &[
                "host",
                "x-amz-content-sha256",
                "x-amz-date",
                "x-amz-security-token",
            ],
            payload_hash,
        );
        headers.insert("authorization", auth.parse().unwrap());

        let err = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            Some(&token_key),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, ProxyError::SignatureDoesNotMatch),
            "expected SignatureDoesNotMatch, got: {:?}",
            err
        );
    });
}

#[test]
fn disabled_credential_is_rejected_before_sig_check() {
    run(async {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let mut config = MockConfig::with_credential(secret);
        config.credentials[0].enabled = false;

        let headers = make_signed_headers("AKIAIOSFODNN7EXAMPLE", secret);

        let err = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            None,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ProxyError::AccessDenied));
    });
}

// ── SigV4 spec compliance tests ──────────────────────────────────

/// Validate our SigV4 implementation against the official AWS test suite.
/// Test vector: "get-vanilla" from
/// https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html
#[test]
fn sigv4_test_vector_get_vanilla() {
    let access_key_id = "AKIDEXAMPLE";
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let date_stamp = "20150830";
    let amz_date = "20150830T123600Z";
    let payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let mut headers = HeaderMap::new();
    headers.insert("host", "example.amazonaws.com".parse().unwrap());
    headers.insert("x-amz-date", amz_date.parse().unwrap());

    let auth = SigV4Auth {
        access_key_id: access_key_id.to_string(),
        date_stamp: date_stamp.to_string(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
        signed_headers: vec!["host".to_string(), "x-amz-date".to_string()],
        signature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31".to_string(),
    };

    let result = verify_sigv4_signature(
        &http::Method::GET,
        "/",
        "",
        &headers,
        &auth,
        secret,
        payload_hash,
    )
    .unwrap();

    assert!(result, "AWS SigV4 test vector 'get-vanilla' must pass");
}

/// Test vector: "get-vanilla-query-order-key" — verifies query parameter sorting.
#[test]
fn sigv4_test_vector_query_order() {
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let date_stamp = "20150830";
    let amz_date = "20150830T123600Z";
    let payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let mut headers = HeaderMap::new();
    headers.insert("host", "example.amazonaws.com".parse().unwrap());
    headers.insert("x-amz-date", amz_date.parse().unwrap());

    let auth = SigV4Auth {
        access_key_id: "AKIDEXAMPLE".to_string(),
        date_stamp: date_stamp.to_string(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
        signed_headers: vec!["host".to_string(), "x-amz-date".to_string()],
        signature: "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500".to_string(),
    };

    // Pass UNSORTED query — our canonicalization should sort to Param1=value1&Param2=value2
    let result = verify_sigv4_signature(
        &http::Method::GET,
        "/",
        "Param2=value2&Param1=value1",
        &headers,
        &auth,
        secret,
        payload_hash,
    )
    .unwrap();

    assert!(
        result,
        "AWS SigV4 test vector 'get-vanilla-query-order-key' must pass"
    );
}

/// Realistic S3 ListObjectsV2 request with host:port, security token,
/// and unsorted query parameters — mirrors what `aws s3 ls` sends.
#[test]
fn sigv4_list_objects_with_security_token_and_port() {
    let secret = "TempSecretKey1234567890EXAMPLE000000000000";
    let session_token = "FwoGZXIvYXdzEBYaDGFiY2RlZjEyMzQ1Ng";
    let date_stamp = "20240101";
    let amz_date = "20240101T000000Z";
    let payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let mut headers = HeaderMap::new();
    headers.insert("host", "localhost:8787".parse().unwrap());
    headers.insert("x-amz-date", amz_date.parse().unwrap());
    headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());
    headers.insert("x-amz-security-token", session_token.parse().unwrap());

    // Sign with sorted query (as AWS SDKs do)
    let auth = sign_request(
        &http::Method::GET,
        "/private-uploads",
        "list-type=2&prefix=&delimiter=%2F&encoding-type=url",
        &headers,
        "ASIATEMP1234EXAMPLE",
        secret,
        date_stamp,
        amz_date,
        "us-east-1",
        &[
            "host",
            "x-amz-content-sha256",
            "x-amz-date",
            "x-amz-security-token",
        ],
        payload_hash,
    );
    headers.insert("authorization", auth.parse().unwrap());

    // Verify with UNSORTED query (as it arrives from the raw URL)
    let sig = parse_sigv4_auth(headers.get("authorization").unwrap().to_str().unwrap()).unwrap();

    let result = verify_sigv4_signature(
        &http::Method::GET,
        "/private-uploads",
        "list-type=2&prefix=&delimiter=%2F&encoding-type=url",
        &headers,
        &sig,
        secret,
        payload_hash,
    )
    .unwrap();

    assert!(
        result,
        "S3 ListObjects with security token and host:port must verify"
    );
}

// ── Sealed token tests ──────────────────────────────────────────

#[test]
fn sealed_token_round_trip() {
    use crate::sealed_token::TokenKey;
    use crate::types::AccessScope;

    run(async {
        let key_bytes = [0x42u8; 32];
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_bytes);
        let token_key = TokenKey::from_base64(&encoded).unwrap();

        let secret = "TempSecretKey1234567890EXAMPLE000000000000";
        let creds = TemporaryCredentials {
            access_key_id: "ASIATEMP1234EXAMPLE".into(),
            secret_access_key: secret.into(),
            session_token: String::new(), // will be replaced by seal
            expiration: chrono::Utc::now() + chrono::Duration::hours(1),
            allowed_scopes: vec![AccessScope {
                bucket: "test-bucket".into(),
                prefixes: vec![],
                actions: vec![Action::GetObject],
            }],
            assumed_role_id: "role-1".into(),
            source_identity: "test".into(),
        };

        let sealed = token_key.seal(&creds).unwrap();
        let config = MockConfig::empty();

        let date_stamp = "20240101";
        let amz_date = "20240101T000000Z";
        let payload_hash = "UNSIGNED-PAYLOAD";

        let mut headers = HeaderMap::new();
        headers.insert("host", "s3.example.com".parse().unwrap());
        headers.insert("x-amz-date", amz_date.parse().unwrap());
        headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());
        headers.insert("x-amz-security-token", sealed.parse().unwrap());

        let auth = sign_request(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            "ASIATEMP1234EXAMPLE",
            secret,
            date_stamp,
            amz_date,
            "us-east-1",
            &[
                "host",
                "x-amz-content-sha256",
                "x-amz-date",
                "x-amz-security-token",
            ],
            payload_hash,
        );
        headers.insert("authorization", auth.parse().unwrap());

        let identity = resolve_identity(
            &http::Method::GET,
            "/test-bucket/key.txt",
            "",
            &headers,
            &config,
            Some(&token_key),
        )
        .await
        .unwrap();

        assert!(matches!(
            identity,
            crate::types::ResolvedIdentity::Temporary { .. }
        ));
    });
}
