//! AWS IAM identity verification via `GetCallerIdentity`.
//!
//! Allows AWS services to authenticate by presenting a signed
//! `sts:GetCallerIdentity` request. The proxy forwards the signed request
//! to AWS STS, which verifies the signature and returns the caller's
//! identity (account, ARN, user ID). The proxy then maps the identity
//! to a configured role.
//!
//! This follows the same pattern used by HashiCorp Vault's `aws` auth method.

use base64::Engine;
use multistore::error::ProxyError;
use serde::Deserialize;
use std::collections::HashMap;

/// Verified AWS caller identity returned by `GetCallerIdentity`.
#[derive(Debug, Clone)]
pub struct AwsCallerIdentity {
    pub account: String,
    pub arn: String,
    pub user_id: String,
}

/// Parsed `AssumeRoleWithAWSIdentity` request parameters.
#[derive(Debug, Clone)]
pub struct AwsIdentityRequest {
    pub role_arn: String,
    pub duration_seconds: Option<u64>,
    pub iam_request_url: String,
    pub iam_request_body: String,
    pub iam_request_headers: HashMap<String, String>,
}

// ── STS URL validation ──────────────────────────────────────────────

/// Allowed STS hostnames. The proxy only forwards signed requests to
/// these hosts, preventing an attacker from pointing at a controlled
/// server that returns fake identity.
fn validate_sts_url(url: &str) -> Result<url::Url, ProxyError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| ProxyError::InvalidRequest(format!("invalid STS URL: {}", e)))?;

    if parsed.scheme() != "https" {
        return Err(ProxyError::InvalidRequest("STS URL must use HTTPS".into()));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ProxyError::InvalidRequest("STS URL missing host".into()))?;

    // Allow: sts.amazonaws.com, sts.<region>.amazonaws.com,
    //        sts-fips.<region>.amazonaws.com
    let valid = host == "sts.amazonaws.com"
        || (host.starts_with("sts.") && host.ends_with(".amazonaws.com"))
        || (host.starts_with("sts-fips.") && host.ends_with(".amazonaws.com"));

    if !valid {
        return Err(ProxyError::InvalidRequest(format!(
            "STS URL host '{}' is not a valid AWS STS endpoint",
            host,
        )));
    }

    Ok(parsed)
}

// ── GetCallerIdentity XML response parsing ──────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename = "GetCallerIdentityResponse")]
struct GetCallerIdentityResponse {
    #[serde(rename = "GetCallerIdentityResult")]
    result: GetCallerIdentityResult,
}

#[derive(Debug, Deserialize)]
struct GetCallerIdentityResult {
    #[serde(rename = "Account")]
    account: String,
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "UserId")]
    user_id: String,
}

fn parse_caller_identity_xml(xml: &str) -> Result<AwsCallerIdentity, ProxyError> {
    let resp: GetCallerIdentityResponse = quick_xml::de::from_str(xml).map_err(|e| {
        ProxyError::InvalidRequest(format!("failed to parse GetCallerIdentity response: {}", e))
    })?;

    Ok(AwsCallerIdentity {
        account: resp.result.account,
        arn: resp.result.arn,
        user_id: resp.result.user_id,
    })
}

// ── Request parsing ─────────────────────────────────────────────────

/// Decode a base64url-or-standard-encoded string.
fn b64_decode(s: &str) -> Result<String, ProxyError> {
    // Try URL-safe first, then standard base64 (be permissive like Vault)
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .map_err(|e| ProxyError::InvalidRequest(format!("base64 decode error: {}", e)))?;

    String::from_utf8(bytes)
        .map_err(|e| ProxyError::InvalidRequest(format!("invalid UTF-8 in base64 payload: {}", e)))
}

/// Try to parse an `AssumeRoleWithAWSIdentity` request from query parameters.
///
/// Query parameters (following Vault's convention):
/// - `Action=AssumeRoleWithAWSIdentity`
/// - `RoleArn=<role_id>`
/// - `IamRequestUrl=<base64-encoded STS URL>`
/// - `IamRequestBody=<base64-encoded request body>`
/// - `IamRequestHeaders=<base64-encoded JSON headers>`
/// - `DurationSeconds=<optional>`
///
/// Returns `None` if the query does not contain `Action=AssumeRoleWithAWSIdentity`.
pub fn try_parse_aws_identity_request(
    query: Option<&str>,
) -> Option<Result<AwsIdentityRequest, ProxyError>> {
    let q = query?;
    let params: Vec<(String, String)> = url::form_urlencoded::parse(q.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let action = params.iter().find(|(k, _)| k == "Action");
    match action {
        Some((_, value)) if value == "AssumeRoleWithAWSIdentity" => {}
        _ => return None,
    }

    Some(parse_aws_identity_params(&params))
}

fn parse_aws_identity_params(
    params: &[(String, String)],
) -> Result<AwsIdentityRequest, ProxyError> {
    let role_arn = params
        .iter()
        .find(|(k, _)| k == "RoleArn")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| ProxyError::InvalidRequest("missing RoleArn".into()))?;

    let iam_request_url = params
        .iter()
        .find(|(k, _)| k == "IamRequestUrl")
        .map(|(_, v)| b64_decode(v))
        .ok_or_else(|| ProxyError::InvalidRequest("missing IamRequestUrl".into()))??;

    let iam_request_body = params
        .iter()
        .find(|(k, _)| k == "IamRequestBody")
        .map(|(_, v)| b64_decode(v))
        .ok_or_else(|| ProxyError::InvalidRequest("missing IamRequestBody".into()))??;

    let iam_request_headers_json = params
        .iter()
        .find(|(k, _)| k == "IamRequestHeaders")
        .map(|(_, v)| b64_decode(v))
        .ok_or_else(|| ProxyError::InvalidRequest("missing IamRequestHeaders".into()))??;

    let iam_request_headers: HashMap<String, String> =
        serde_json::from_str(&iam_request_headers_json).map_err(|e| {
            ProxyError::InvalidRequest(format!("invalid IamRequestHeaders JSON: {}", e))
        })?;

    let duration_seconds = params
        .iter()
        .find(|(k, _)| k == "DurationSeconds")
        .and_then(|(_, v)| v.parse().ok());

    Ok(AwsIdentityRequest {
        role_arn,
        duration_seconds,
        iam_request_url,
        iam_request_body,
        iam_request_headers,
    })
}

// ── Identity verification via AWS STS ───────────────────────────────

/// Forward the client's signed `GetCallerIdentity` request to AWS STS
/// and return the verified caller identity.
pub async fn verify_aws_identity(
    client: &reqwest::Client,
    request: &AwsIdentityRequest,
) -> Result<AwsCallerIdentity, ProxyError> {
    let url = validate_sts_url(&request.iam_request_url)?;

    let mut req_builder = client.post(url);
    for (key, value) in &request.iam_request_headers {
        // Skip the Host header — reqwest sets it from the URL
        if key.eq_ignore_ascii_case("host") {
            continue;
        }
        req_builder = req_builder.header(key.as_str(), value.as_str());
    }
    req_builder = req_builder.body(request.iam_request_body.clone());

    let response = req_builder.send().await.map_err(|e| {
        tracing::warn!(error = %e, "failed to forward GetCallerIdentity to AWS STS");
        ProxyError::Internal(format!("STS request failed: {}", e))
    })?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| ProxyError::Internal(format!("failed to read STS response: {}", e)))?;

    if !status.is_success() {
        tracing::warn!(
            status = %status,
            "AWS STS rejected GetCallerIdentity request"
        );
        return Err(ProxyError::AccessDenied);
    }

    parse_caller_identity_xml(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── URL validation ──────────────────────────────────────────────

    #[test]
    fn test_validate_sts_url_global() {
        validate_sts_url("https://sts.amazonaws.com/").unwrap();
    }

    #[test]
    fn test_validate_sts_url_regional() {
        validate_sts_url("https://sts.us-east-1.amazonaws.com/").unwrap();
        validate_sts_url("https://sts.eu-west-1.amazonaws.com/").unwrap();
        validate_sts_url("https://sts.ap-southeast-1.amazonaws.com/").unwrap();
    }

    #[test]
    fn test_validate_sts_url_fips() {
        validate_sts_url("https://sts-fips.us-east-1.amazonaws.com/").unwrap();
    }

    #[test]
    fn test_validate_sts_url_rejects_http() {
        let err = validate_sts_url("http://sts.amazonaws.com/").unwrap_err();
        assert!(err.to_string().contains("HTTPS"), "{}", err);
    }

    #[test]
    fn test_validate_sts_url_rejects_custom_host() {
        let err = validate_sts_url("https://sts.evil.com/").unwrap_err();
        assert!(err.to_string().contains("not a valid AWS STS"), "{}", err);
    }

    #[test]
    fn test_validate_sts_url_rejects_subdomain_trick() {
        let err = validate_sts_url("https://sts.amazonaws.com.evil.com/").unwrap_err();
        assert!(err.to_string().contains("not a valid AWS STS"), "{}", err);
    }

    // ── XML parsing ─────────────────────────────────────────────────

    #[test]
    fn test_parse_caller_identity_response() {
        let xml = r#"
            <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
                <GetCallerIdentityResult>
                    <Arn>arn:aws:sts::123456789012:assumed-role/EtlPipeline/i-0abc123</Arn>
                    <UserId>AROAEXAMPLE:i-0abc123</UserId>
                    <Account>123456789012</Account>
                </GetCallerIdentityResult>
                <ResponseMetadata>
                    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
                </ResponseMetadata>
            </GetCallerIdentityResponse>
        "#;
        let identity = parse_caller_identity_xml(xml).unwrap();
        assert_eq!(identity.account, "123456789012");
        assert_eq!(
            identity.arn,
            "arn:aws:sts::123456789012:assumed-role/EtlPipeline/i-0abc123"
        );
        assert_eq!(identity.user_id, "AROAEXAMPLE:i-0abc123");
    }

    #[test]
    fn test_parse_caller_identity_error_xml() {
        let xml = r#"
            <ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
                <Error>
                    <Code>InvalidIdentityToken</Code>
                    <Message>Token is expired</Message>
                </Error>
            </ErrorResponse>
        "#;
        assert!(parse_caller_identity_xml(xml).is_err());
    }

    // ── Request parsing ─────────────────────────────────────────────

    #[test]
    fn test_not_aws_identity_request() {
        assert!(try_parse_aws_identity_request(None).is_none());
        assert!(try_parse_aws_identity_request(Some("Action=ListBuckets")).is_none());
        assert!(try_parse_aws_identity_request(Some(
            "Action=AssumeRoleWithWebIdentity&RoleArn=r&WebIdentityToken=t"
        ))
        .is_none());
    }

    #[test]
    fn test_parse_aws_identity_request() {
        use base64::engine::general_purpose::STANDARD;

        let url_b64 = STANDARD.encode("https://sts.amazonaws.com/");
        let body_b64 = STANDARD.encode("Action=GetCallerIdentity&Version=2011-06-15");
        let headers_b64 = STANDARD
            .encode(r#"{"Authorization":"AWS4-HMAC-SHA256 ...","X-Amz-Date":"20260305T120000Z"}"#);

        let query = format!(
            "Action=AssumeRoleWithAWSIdentity&RoleArn=my-aws-role&IamRequestUrl={}&IamRequestBody={}&IamRequestHeaders={}",
            url_b64, body_b64, headers_b64
        );

        let req = try_parse_aws_identity_request(Some(&query))
            .unwrap()
            .unwrap();
        assert_eq!(req.role_arn, "my-aws-role");
        assert_eq!(req.iam_request_url, "https://sts.amazonaws.com/");
        assert_eq!(
            req.iam_request_body,
            "Action=GetCallerIdentity&Version=2011-06-15"
        );
        assert!(req.iam_request_headers.contains_key("Authorization"));
        assert_eq!(req.duration_seconds, None);
    }

    #[test]
    fn test_parse_aws_identity_request_with_duration() {
        use base64::engine::general_purpose::STANDARD;

        let url_b64 = STANDARD.encode("https://sts.amazonaws.com/");
        let body_b64 = STANDARD.encode("Action=GetCallerIdentity&Version=2011-06-15");
        let headers_b64 = STANDARD.encode(r#"{"Authorization":"sig"}"#);

        let query = format!(
            "Action=AssumeRoleWithAWSIdentity&RoleArn=r&IamRequestUrl={}&IamRequestBody={}&IamRequestHeaders={}&DurationSeconds=1800",
            url_b64, body_b64, headers_b64
        );

        let req = try_parse_aws_identity_request(Some(&query))
            .unwrap()
            .unwrap();
        assert_eq!(req.duration_seconds, Some(1800));
    }

    #[test]
    fn test_parse_aws_identity_request_missing_params() {
        let query = "Action=AssumeRoleWithAWSIdentity&RoleArn=r";
        let err = try_parse_aws_identity_request(Some(query))
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("missing IamRequestUrl"), "{}", err);
    }
}
