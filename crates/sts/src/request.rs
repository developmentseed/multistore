//! STS request parsing.
//!
//! Extracts `AssumeRoleWithWebIdentity` parameters from a form-urlencoded
//! parameter string — a query string, or the body of an
//! `application/x-www-form-urlencoded` `POST` (the shape AWS SDKs send);
//! `try_handle_sts` checks both.

use multistore::error::ProxyError;

/// Parsed STS `AssumeRoleWithWebIdentity` request parameters.
#[derive(Debug, Clone)]
pub struct StsRequest {
    /// The ARN of the IAM role to assume.
    pub role_arn: String,
    /// The OIDC identity token provided by the caller.
    pub web_identity_token: String,
    /// Optional session duration in seconds.
    pub duration_seconds: Option<u64>,
}

/// Try to parse an STS request from a form-urlencoded parameter string — a
/// query string, or a form-encoded `POST` body (the two places AWS STS accepts
/// parameters).
///
/// Returns `None` if the string does not contain `Action=AssumeRoleWithWebIdentity`
/// (i.e., this is not an STS request). Returns `Some(Ok(..))` on success or
/// `Some(Err(..))` if it is an STS request but required parameters are missing.
pub fn try_parse_sts_request(query: Option<&str>) -> Option<Result<StsRequest, ProxyError>> {
    let q = query?;
    let params: Vec<(String, String)> = url::form_urlencoded::parse(q.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let action = params.iter().find(|(k, _)| k == "Action");
    match action {
        Some((_, value)) if value == "AssumeRoleWithWebIdentity" => {}
        _ => return None,
    }

    Some(parse_sts_params(&params))
}

/// Whether a form-urlencoded parameter string (query or `POST` body) requests
/// `Action=GetCallerIdentity`.
///
/// `GetCallerIdentity` carries no other parameters worth extracting — it is
/// authenticated entirely by the request's SigV4 signature — so a boolean is
/// all the caller needs.
pub fn is_get_caller_identity(params: Option<&str>) -> bool {
    let Some(q) = params else { return false };
    url::form_urlencoded::parse(q.as_bytes())
        .any(|(k, v)| k == "Action" && v == "GetCallerIdentity")
}

fn parse_sts_params(params: &[(String, String)]) -> Result<StsRequest, ProxyError> {
    let role_arn = params
        .iter()
        .find(|(k, _)| k == "RoleArn")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| ProxyError::InvalidRequest("missing RoleArn".into()))?;

    let web_identity_token = params
        .iter()
        .find(|(k, _)| k == "WebIdentityToken")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| ProxyError::InvalidRequest("missing WebIdentityToken".into()))?;

    let duration_seconds = params
        .iter()
        .find(|(k, _)| k == "DurationSeconds")
        .and_then(|(_, v)| v.parse().ok());

    Ok(StsRequest {
        role_arn,
        web_identity_token,
        duration_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_sts_request() {
        assert!(try_parse_sts_request(None).is_none());
        assert!(try_parse_sts_request(Some("prefix=foo/")).is_none());
        assert!(try_parse_sts_request(Some("Action=ListBuckets")).is_none());
    }

    #[test]
    fn test_valid_sts_request() {
        let query = "Action=AssumeRoleWithWebIdentity&RoleArn=my-role&WebIdentityToken=tok123";
        let result = try_parse_sts_request(Some(query)).unwrap().unwrap();
        assert_eq!(result.role_arn, "my-role");
        assert_eq!(result.web_identity_token, "tok123");
        assert_eq!(result.duration_seconds, None);
    }

    #[test]
    fn test_sts_request_with_duration() {
        let query =
            "Action=AssumeRoleWithWebIdentity&RoleArn=r&WebIdentityToken=t&DurationSeconds=7200";
        let result = try_parse_sts_request(Some(query)).unwrap().unwrap();
        assert_eq!(result.duration_seconds, Some(7200));
    }

    #[test]
    fn test_missing_role_arn() {
        let query = "Action=AssumeRoleWithWebIdentity&WebIdentityToken=tok";
        let result = try_parse_sts_request(Some(query)).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_web_identity_token() {
        let query = "Action=AssumeRoleWithWebIdentity&RoleArn=role";
        let result = try_parse_sts_request(Some(query)).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_is_get_caller_identity() {
        assert!(is_get_caller_identity(Some(
            "Action=GetCallerIdentity&Version=2011-06-15"
        )));
        // Order-independent and tolerant of extra params.
        assert!(is_get_caller_identity(Some(
            "Version=2011-06-15&Action=GetCallerIdentity"
        )));
        assert!(!is_get_caller_identity(Some(
            "Action=AssumeRoleWithWebIdentity&RoleArn=r&WebIdentityToken=t"
        )));
        assert!(!is_get_caller_identity(Some("prefix=foo/")));
        assert!(!is_get_caller_identity(None));
    }
}
