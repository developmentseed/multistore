//! OIDC/STS authentication for the S3 proxy gateway.
//!
//! This crate implements STS-style token exchange APIs, allowing workloads to
//! exchange identity proofs for temporary S3 credentials scoped to specific
//! buckets and prefixes.
//!
//! # Supported auth methods
//!
//! - **`AssumeRoleWithWebIdentity`** — exchange an OIDC JWT for credentials
//!   (e.g., GitHub Actions, Auth0)
//! - **`AssumeRoleWithAWSIdentity`** — exchange a signed AWS `GetCallerIdentity`
//!   request for credentials (any AWS service with IAM credentials)
//!
//! # Integration
//!
//! Register [`route_handler::StsRouteHandler`] with the gateway to intercept
//! STS requests automatically:
//!
//! ```rust,ignore
//! let gateway = Gateway::new(backend, resolver)
//!     .with_route_handler(StsRouteHandler::new(config, jwks_cache, token_key));
//! ```
//!
//! # OIDC Flow
//!
//! 1. Client obtains a JWT from their OIDC provider (e.g., GitHub Actions ID token)
//! 2. Client calls `AssumeRoleWithWebIdentity` with the JWT and desired role
//! 3. This crate validates the JWT against the OIDC provider's JWKS
//! 4. Checks trust policy (issuer, audience, subject conditions)
//! 5. Mints temporary credentials (AccessKeyId/SecretAccessKey/SessionToken)
//! 6. Returns credentials to the client
//!
//! # AWS IAM Flow
//!
//! 1. Client signs a `GetCallerIdentity` request using its IAM credentials
//! 2. Client calls `AssumeRoleWithAWSIdentity` with the signed request and desired role
//! 3. Proxy forwards the signed request to AWS STS to verify identity
//! 4. Checks trust policy (account, ARN subject conditions)
//! 5. Mints temporary credentials
//! 6. Returns credentials to the client
//!
//! The client then uses these credentials to sign S3 requests normally.

pub mod aws_identity;
pub mod jwks;
pub mod request;
pub mod responses;
pub mod route_handler;
pub mod sts;

use aws_identity::{verify_aws_identity, AwsCallerIdentity};
use base64::Engine;
pub use jwks::JwksCache;
use multistore::config::ConfigProvider;
use multistore::error::ProxyError;
use multistore::sealed_token::TokenKey;
use multistore::types::TemporaryCredentials;
pub use request::try_parse_sts_request;
use request::StsRequest;
pub use responses::{build_sts_error_response, build_sts_response};

/// Try to handle an STS request. Returns `Some((status, xml))` if the query
/// contained an STS action, or `None` if it wasn't an STS request.
///
/// Supports both `AssumeRoleWithWebIdentity` (OIDC) and
/// `AssumeRoleWithAWSIdentity` (IAM identity verification).
///
/// Requires a `TokenKey` — minted credentials are encrypted into the session
/// token itself, so no server-side storage is needed. If `token_key` is `None`
/// and an STS request arrives, an error response is returned.
pub async fn try_handle_sts<C: ConfigProvider>(
    query: Option<&str>,
    config: &C,
    jwks_cache: &JwksCache,
    http_client: &reqwest::Client,
    token_key: Option<&TokenKey>,
) -> Option<(u16, String)> {
    // Try OIDC first
    if let Some(sts_result) = try_parse_sts_request(query) {
        let (status, xml) = match sts_result {
            Ok(sts_request) => {
                let Some(key) = token_key else {
                    tracing::error!("STS request received but SESSION_TOKEN_KEY is not configured");
                    return Some(build_sts_error_response(&ProxyError::ConfigError(
                        "STS requires SESSION_TOKEN_KEY to be configured".into(),
                    )));
                };
                match assume_role_with_web_identity(
                    config,
                    &sts_request,
                    "STSPRXY",
                    jwks_cache,
                    key,
                )
                .await
                {
                    Ok(creds) => build_sts_response(&creds),
                    Err(e) => {
                        tracing::warn!(error = %e, "STS OIDC request failed");
                        build_sts_error_response(&e)
                    }
                }
            }
            Err(e) => build_sts_error_response(&e),
        };
        return Some((status, xml));
    }

    // Try AWS IAM identity verification
    if let Some(aws_result) = aws_identity::try_parse_aws_identity_request(query) {
        let (status, xml) = match aws_result {
            Ok(aws_request) => {
                let Some(key) = token_key else {
                    tracing::error!("STS request received but SESSION_TOKEN_KEY is not configured");
                    return Some(build_sts_error_response(&ProxyError::ConfigError(
                        "STS requires SESSION_TOKEN_KEY to be configured".into(),
                    )));
                };
                match handle_aws_identity_request(config, &aws_request, http_client, key).await {
                    Ok(creds) => build_sts_response(&creds),
                    Err(e) => {
                        tracing::warn!(error = %e, "STS AWS IAM request failed");
                        build_sts_error_response(&e)
                    }
                }
            }
            Err(e) => build_sts_error_response(&e),
        };
        return Some((status, xml));
    }

    None
}

/// Decode JWT header and claims without signature verification.
fn jwt_decode_unverified(
    token: &str,
) -> Result<(serde_json::Value, serde_json::Value), ProxyError> {
    let mut parts = token.splitn(3, '.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| ProxyError::InvalidOidcToken("malformed JWT".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| ProxyError::InvalidOidcToken("malformed JWT".into()))?;

    let decode = |s: &str| -> Result<serde_json::Value, ProxyError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| ProxyError::InvalidOidcToken(format!("base64url decode error: {}", e)))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| ProxyError::InvalidOidcToken(format!("invalid JWT JSON: {}", e)))
    };

    Ok((decode(header_b64)?, decode(payload_b64)?))
}

/// Validate an OIDC token and mint temporary credentials.
///
/// Credentials are encrypted into a self-contained session token via `token_key`.
/// No server-side credential storage is needed.
pub async fn assume_role_with_web_identity<C: ConfigProvider>(
    config: &C,
    sts_request: &StsRequest,
    key_prefix: &str,
    jwks_cache: &JwksCache,
    token_key: &TokenKey,
) -> Result<TemporaryCredentials, ProxyError> {
    // Look up the role
    let role = config
        .get_role(&sts_request.role_arn)
        .await?
        .ok_or_else(|| ProxyError::RoleNotFound(sts_request.role_arn.to_string()))?;

    // Decode the JWT header and claims without verification to extract issuer and kid
    let (header, insecure_claims) = jwt_decode_unverified(&sts_request.web_identity_token)?;

    let issuer = insecure_claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProxyError::InvalidOidcToken("missing iss claim".into()))?;

    // Verify the issuer is trusted
    if !role.trusted_oidc_issuers.iter().any(|i| i == issuer) {
        return Err(ProxyError::InvalidOidcToken(format!(
            "untrusted issuer: {}",
            issuer
        )));
    }

    // Fail fast on unsupported algorithms before making any network requests
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "RS256" {
        return Err(ProxyError::InvalidOidcToken(format!(
            "unsupported JWT algorithm: {}",
            alg
        )));
    }

    // Fetch JWKS (using cache) and verify the token
    let jwks = jwks_cache.get_or_fetch(issuer).await?;
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProxyError::InvalidOidcToken("JWT missing kid".into()))?;

    let key = jwks::find_key(&jwks, kid)?;
    let claims = jwks::verify_token(&sts_request.web_identity_token, key, issuer, &role)?;

    // Check subject conditions
    let subject = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");

    if !role.subject_conditions.is_empty() {
        let matches = role
            .subject_conditions
            .iter()
            .any(|pattern| subject_matches(subject, pattern));
        if !matches {
            return Err(ProxyError::InvalidOidcToken(format!(
                "subject '{}' does not match any conditions",
                subject
            )));
        }
    }

    // Mint temporary credentials (AWS enforces 900s minimum)
    const MIN_SESSION_DURATION_SECS: u64 = 900;
    let duration = sts_request
        .duration_seconds
        .unwrap_or(3600)
        .clamp(MIN_SESSION_DURATION_SECS, role.max_session_duration_secs);

    let mut creds = sts::mint_temporary_credentials(&role, subject, duration, key_prefix, &claims);

    // Encrypt the full credentials into the session token — stateless, no storage needed
    creds.session_token = token_key.seal(&creds)?;

    Ok(creds)
}

/// Verify AWS IAM identity and mint temporary credentials.
async fn handle_aws_identity_request<C: ConfigProvider>(
    config: &C,
    aws_request: &aws_identity::AwsIdentityRequest,
    http_client: &reqwest::Client,
    token_key: &TokenKey,
) -> Result<TemporaryCredentials, ProxyError> {
    // Forward the signed GetCallerIdentity request to AWS STS
    let identity = verify_aws_identity(http_client, aws_request).await?;

    tracing::info!(
        account = %identity.account,
        arn = %identity.arn,
        "verified AWS IAM identity"
    );

    assume_role_with_aws_identity(
        config,
        &aws_request.role_arn,
        aws_request.duration_seconds,
        &identity,
        "STSPRXY",
        token_key,
    )
    .await
}

/// Verify a caller's AWS identity against role trust policy and mint credentials.
///
/// Checks that the caller's AWS account is in `trusted_aws_accounts` and
/// that the caller's ARN matches `subject_conditions`. Then mints temporary
/// credentials using the same pipeline as the OIDC flow.
pub async fn assume_role_with_aws_identity<C: ConfigProvider>(
    config: &C,
    role_arn: &str,
    duration_seconds: Option<u64>,
    identity: &AwsCallerIdentity,
    key_prefix: &str,
    token_key: &TokenKey,
) -> Result<TemporaryCredentials, ProxyError> {
    // Look up the role
    let role = config
        .get_role(role_arn)
        .await?
        .ok_or_else(|| ProxyError::RoleNotFound(role_arn.to_string()))?;

    // Verify the caller's account is trusted
    if !role
        .trusted_aws_accounts
        .iter()
        .any(|a| a == &identity.account)
    {
        tracing::warn!(
            account = %identity.account,
            role = %role_arn,
            "AWS account not trusted by role"
        );
        return Err(ProxyError::AccessDenied);
    }

    // Check subject conditions against the caller's ARN
    if !role.subject_conditions.is_empty() {
        let matches = role
            .subject_conditions
            .iter()
            .any(|pattern| subject_matches(&identity.arn, pattern));
        if !matches {
            tracing::warn!(
                arn = %identity.arn,
                role = %role_arn,
                "ARN does not match any subject conditions"
            );
            return Err(ProxyError::AccessDenied);
        }
    }

    // Build synthetic claims for template variable resolution in scopes
    let claims = serde_json::json!({
        "sub": &identity.arn,
        "aws_account": &identity.account,
        "aws_arn": &identity.arn,
        "aws_user_id": &identity.user_id,
    });

    // Mint temporary credentials
    const MIN_SESSION_DURATION_SECS: u64 = 900;
    let duration = duration_seconds
        .unwrap_or(3600)
        .clamp(MIN_SESSION_DURATION_SECS, role.max_session_duration_secs);

    let mut creds =
        sts::mint_temporary_credentials(&role, &identity.arn, duration, key_prefix, &claims);

    // Encrypt into session token
    creds.session_token = token_key.seal(&creds)?;

    Ok(creds)
}

/// Simple glob-style matching for subject conditions.
/// Supports `*` as a wildcard for any sequence of characters.
fn subject_matches(subject: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return subject == pattern;
    }

    let mut remaining = subject;

    // First part must be a prefix
    if !parts[0].is_empty() {
        if !remaining.starts_with(parts[0]) {
            return false;
        }
        remaining = &remaining[parts[0].len()..];
    }

    // Middle parts must appear in order
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        match remaining.find(part) {
            Some(idx) => remaining = &remaining[idx + part.len()..],
            None => return false,
        }
    }

    // Last part must be a suffix
    let last = parts.last().unwrap();
    if !last.is_empty() {
        return remaining.ends_with(last);
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subject_matching() {
        // Trailing wildcard
        assert!(subject_matches(
            "repo:org/repo:ref:refs/heads/main",
            "repo:org/repo:*"
        ));

        // Match-all wildcard
        assert!(subject_matches("repo:org/repo:ref:refs/heads/main", "*"));

        // Exact match (no wildcards)
        assert!(subject_matches(
            "repo:org/repo:ref:refs/heads/main",
            "repo:org/repo:ref:refs/heads/main"
        ));

        // Wrong prefix
        assert!(!subject_matches(
            "repo:org/repo:ref:refs/heads/main",
            "repo:other/*"
        ));

        // Multiple wildcards
        assert!(subject_matches(
            "repo:org/repo:ref:refs/heads/main",
            "repo:org/*:ref:refs/heads/*"
        ));
    }

    #[test]
    fn test_subject_matching_exact() {
        assert!(subject_matches("abc", "abc"));
        assert!(!subject_matches("abc", "abcd"));
        assert!(!subject_matches("abcd", "abc"));
        assert!(!subject_matches("", "abc"));
        assert!(subject_matches("", ""));
    }

    #[test]
    fn test_subject_matching_leading_wildcard() {
        assert!(subject_matches("anything", "*"));
        assert!(subject_matches("", "*"));
        assert!(subject_matches("foo", "*foo"));
        assert!(subject_matches("xfoo", "*foo"));
        assert!(!subject_matches("foox", "*foo"));
    }

    #[test]
    fn test_subject_matching_trailing_wildcard() {
        assert!(subject_matches("foo", "foo*"));
        assert!(subject_matches("foobar", "foo*"));
        assert!(!subject_matches("xfoo", "foo*"));
    }

    #[test]
    fn test_subject_matching_middle_wildcard() {
        assert!(subject_matches("foobar", "foo*bar"));
        assert!(subject_matches("fooXbar", "foo*bar"));
        assert!(subject_matches("fooXYZbar", "foo*bar"));
        assert!(!subject_matches("fooXbaz", "foo*bar"));
        assert!(!subject_matches("xfoobar", "foo*bar"));
    }

    #[test]
    fn test_subject_matching_multiple_wildcards() {
        // Two wildcards with repeated literal
        assert!(subject_matches("axbb", "a*b*b"));
        assert!(!subject_matches("axb", "a*b*b"));

        // Wildcard must not overlap with suffix
        assert!(!subject_matches("abc", "a*bc*c"));
        assert!(subject_matches("abcc", "a*bc*c"));

        // Multiple wildcards requiring non-greedy left-to-right match
        assert!(subject_matches("aab", "*a*ab"));
        assert!(!subject_matches("xab", "*a*ab"));

        // Repeated pattern in subject
        assert!(subject_matches("xababab", "*ab*ab"));
        assert!(!subject_matches("xab", "*ab*ab"));
    }

    #[test]
    fn test_subject_matching_double_wildcard() {
        assert!(subject_matches("anything", "**"));
        assert!(subject_matches("", "**"));
    }

    #[test]
    fn test_subject_matching_empty_subject() {
        assert!(subject_matches("", "*"));
        assert!(!subject_matches("", "a"));
        assert!(subject_matches("", ""));
    }
}
