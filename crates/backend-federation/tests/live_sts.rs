//! Live functional test for outbound federation against **real AWS STS**.
//!
//! This exercises the whole `multistore-backend-federation` primitive end to
//! end: build an `AssumeRoleWithWebIdentity` request, exchange a real OIDC
//! token at real AWS STS, parse the reply, and then prove the returned
//! credentials actually work by reading the private S3 bucket with them (via
//! `object_store`, exactly how multistore uses them).
//!
//! It is `#[ignore]`d so it stays out of the ordinary unit-test suite (and
//! local `cargo test`), but the dedicated `live-federation` CI job runs it with
//! `--ignored` on every push and it **panics (fails) when the required
//! environment is absent** — so a configured role + bucket is enforced rather
//! than silently skipped.
//!
//! ## Required environment
//!
//! - `MULTISTORE_TEST_ROLE_ARN` — IAM role to assume. **If unset, the test
//!   fails.**
//! - `MULTISTORE_TEST_BUCKET` — private S3 bucket the role can read.
//! - `MULTISTORE_TEST_REGION` — bucket/STS region (default `us-east-1`).
//! - `MULTISTORE_TEST_KEY` — optional object key to `GET`; if unset the test
//!   only `LIST`s (listing alone proves the credentials authenticate).
//!
//! ## Web identity token (one of)
//!
//! - `MULTISTORE_TEST_WEB_IDENTITY_TOKEN` — a raw OIDC JWT to present, or
//! - `ACTIONS_ID_TOKEN_REQUEST_TOKEN` + `ACTIONS_ID_TOKEN_REQUEST_URL` — set
//!   automatically in GitHub Actions jobs with `permissions: id-token: write`;
//!   the test mints a token with audience `sts.amazonaws.com`.
//!
//! The role's trust policy must trust whichever issuer the token comes from
//! (for the GitHub Actions path, `token.actions.githubusercontent.com` with the
//! repo `sub` and `sts.amazonaws.com` audience) and grant `s3:ListBucket`
//! (+ `s3:GetObject` if `MULTISTORE_TEST_KEY` is set) on the test bucket.

use multistore_backend_federation::aws::{parse_response, AssumeRoleWithWebIdentity};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Obtain an OIDC token: an explicit one if provided, else a GitHub Actions
/// token. Returns `None` when neither source is configured.
async fn web_identity_token() -> Option<String> {
    if let Some(token) = env("MULTISTORE_TEST_WEB_IDENTITY_TOKEN") {
        return Some(token);
    }

    let req_token = env("ACTIONS_ID_TOKEN_REQUEST_TOKEN")?;
    let req_url = env("ACTIONS_ID_TOKEN_REQUEST_URL")?;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{req_url}&audience=sts.amazonaws.com"))
        .header("Authorization", format!("bearer {req_token}"))
        .send()
        .await
        .expect("fetch GitHub Actions OIDC token")
        .error_for_status()
        .expect("GitHub Actions OIDC token request failed");
    let body: serde_json::Value = resp.json().await.expect("parse OIDC token JSON");
    Some(
        body.get("value")
            .and_then(|v| v.as_str())
            .expect("OIDC token response missing `value`")
            .to_string(),
    )
}

// `#[ignore]` keeps this out of the ordinary unit-test suite (it needs real AWS
// and would otherwise fail local `cargo test`). The `live-federation` CI job
// runs it with `-- --ignored` on every push and **fails if the required env
// vars are unset** — a configured role + bucket is enforced, never silently
// skipped. Run locally with:
//   MULTISTORE_TEST_ROLE_ARN=… MULTISTORE_TEST_BUCKET=… \
//     cargo test -p multistore-backend-federation --test live_sts -- --ignored --nocapture
#[tokio::test]
#[ignore = "live AWS test; set MULTISTORE_TEST_ROLE_ARN/BUCKET and run with --ignored"]
async fn assume_role_and_read_private_bucket() {
    let role_arn = env("MULTISTORE_TEST_ROLE_ARN")
        .expect("MULTISTORE_TEST_ROLE_ARN must be set to run the live federation test");
    let bucket = env("MULTISTORE_TEST_BUCKET")
        .expect("MULTISTORE_TEST_BUCKET must be set when MULTISTORE_TEST_ROLE_ARN is");
    let region = env("MULTISTORE_TEST_REGION").unwrap_or_else(|| "us-east-1".to_string());

    let Some(token) = web_identity_token().await else {
        panic!(
            "MULTISTORE_TEST_ROLE_ARN is set but no web identity token source is available \
             (set MULTISTORE_TEST_WEB_IDENTITY_TOKEN, or run under GitHub Actions with \
             id-token: write)"
        );
    };

    // ── 1. Build the request with the crate under test and exchange it at
    //       real AWS STS. The caller owns the HTTP; reqwest urlencodes the
    //       unencoded `form_pairs()`.
    let request = AssumeRoleWithWebIdentity {
        role_arn: &role_arn,
        web_identity_token: &token,
        role_session_name: "multistore-itest",
        duration_seconds: Some(900),
        session_policy: None,
    };
    let pairs = request.form_pairs();
    let form: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_ref())).collect();

    let endpoint = AssumeRoleWithWebIdentity::endpoint(&region);
    let body = reqwest::Client::new()
        .post(&endpoint)
        .form(&form)
        .send()
        .await
        .expect("POST to AWS STS")
        .text()
        .await
        .expect("read STS response body");

    // ── 2. Parse with the crate under test. A trust/permission misconfig
    //       surfaces here as a typed `FederationError::Sts`.
    let creds = parse_response(&body)
        .unwrap_or_else(|e| panic!("STS exchange failed: {e}\n--- raw response ---\n{body}"));
    assert!(
        creds.access_key_id.starts_with("ASIA"),
        "expected temporary (ASIA…) access key, got {:?}",
        creds.access_key_id
    );
    assert!(!creds.secret_access_key.is_empty());
    assert!(!creds.session_token.is_empty());

    // ── 3. Prove the credentials actually authenticate against the private
    //       bucket, the same way multistore signs backend requests.
    use object_store::aws::AmazonS3Builder;
    use object_store::{ObjectStore, ObjectStoreExt};

    let store = AmazonS3Builder::new()
        .with_region(&region)
        .with_bucket_name(&bucket)
        .with_access_key_id(&creds.access_key_id)
        .with_secret_access_key(&creds.secret_access_key)
        .with_token(&creds.session_token)
        .build()
        .expect("build S3 store from federated credentials");

    if let Some(key) = env("MULTISTORE_TEST_KEY") {
        let path = object_store::path::Path::from(key.as_str());
        let got = store
            .get(&path)
            .await
            .unwrap_or_else(|e| panic!("GET {key} with federated creds failed: {e}"));
        let bytes = got.bytes().await.expect("read object body");
        assert!(!bytes.is_empty(), "object {key} was empty");
    } else {
        // Listing alone proves the credentials authenticate — an auth failure
        // errors on the first poll; an empty bucket simply yields no items.
        use futures::StreamExt;
        let mut stream = store.list(None);
        if let Some(item) = stream.next().await {
            item.unwrap_or_else(|e| panic!("LIST {bucket} with federated creds failed: {e}"));
        }
    }
}
