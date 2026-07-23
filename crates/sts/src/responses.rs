//! STS XML response serialization.

use multistore::error::ProxyError;
use multistore::types::TemporaryCredentials;
use quick_xml::se::to_string as xml_to_string;
use serde::Serialize;

/// STS AssumeRoleWithWebIdentity response.
#[derive(Debug, Serialize)]
#[serde(rename = "AssumeRoleWithWebIdentityResponse")]
pub struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    pub result: AssumeRoleWithWebIdentityResult,
}

/// The result payload nested inside an `AssumeRoleWithWebIdentityResponse`.
#[derive(Debug, Serialize)]
pub struct AssumeRoleWithWebIdentityResult {
    #[serde(rename = "Credentials")]
    pub credentials: StsCredentials,
    #[serde(rename = "AssumedRoleUser")]
    pub assumed_role_user: AssumedRoleUser,
}

/// Temporary AWS credentials returned by an STS assume-role call.
#[derive(Debug, Serialize)]
pub struct StsCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "SessionToken")]
    pub session_token: String,
    #[serde(rename = "Expiration")]
    pub expiration: String,
}

/// Identity information for the assumed role session.
#[derive(Debug, Serialize)]
pub struct AssumedRoleUser {
    #[serde(rename = "AssumedRoleId")]
    pub assumed_role_id: String,
    #[serde(rename = "Arn")]
    pub arn: String,
}

impl AssumeRoleWithWebIdentityResponse {
    /// Serialize this response to an XML string with an XML declaration header.
    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            xml_to_string(self).unwrap_or_default()
        )
    }
}

/// Build an STS success response (status code + XML body) from temporary credentials.
pub fn build_sts_response(creds: &TemporaryCredentials) -> (u16, String) {
    let response = AssumeRoleWithWebIdentityResponse {
        result: AssumeRoleWithWebIdentityResult {
            credentials: StsCredentials {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
                expiration: creds.expiration.to_rfc3339(),
            },
            assumed_role_user: AssumedRoleUser {
                assumed_role_id: creds.assumed_role_id.clone(),
                arn: creds.assumed_role_id.clone(),
            },
        },
    };
    (200, response.to_xml())
}

/// The fabricated 12-digit AWS account id used in synthetic STS identities.
///
/// The proxy fronts arbitrary S3 backends and has no real AWS account, so
/// `GetCallerIdentity` reports a zero account. Using it consistently in both the
/// account field and the assumed-role ARN keeps the identity document
/// internally coherent for tooling (e.g. `aws-actions/configure-aws-credentials`
/// surfaces `Account` as its `aws-account-id` output).
pub const SYNTHETIC_ACCOUNT_ID: &str = "000000000000";

/// STS `GetCallerIdentity` response.
#[derive(Debug, Serialize)]
#[serde(rename = "GetCallerIdentityResponse")]
struct GetCallerIdentityResponse {
    #[serde(rename = "GetCallerIdentityResult")]
    result: GetCallerIdentityResult,
}

#[derive(Debug, Serialize)]
struct GetCallerIdentityResult {
    #[serde(rename = "Arn")]
    arn: String,
    #[serde(rename = "UserId")]
    user_id: String,
    #[serde(rename = "Account")]
    account: String,
}

/// Build a `GetCallerIdentity` XML document describing an assumed-role session.
///
/// The identity is synthesized from the sealed credentials: `Account` is the
/// fabricated [`SYNTHETIC_ACCOUNT_ID`], and `Arn`/`UserId` are derived from the
/// assumed role id and the OIDC subject that assumed it. `quick_xml` escapes the
/// subject, which may contain characters like `:` and `/` from an OIDC `sub`.
pub fn build_caller_identity_response(creds: &TemporaryCredentials) -> String {
    let response = GetCallerIdentityResponse {
        result: GetCallerIdentityResult {
            arn: format!(
                "arn:aws:sts::{}:assumed-role/{}/{}",
                SYNTHETIC_ACCOUNT_ID, creds.assumed_role_id, creds.source_identity
            ),
            user_id: format!("{}:{}", creds.assumed_role_id, creds.source_identity),
            account: SYNTHETIC_ACCOUNT_ID.to_string(),
        },
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        xml_to_string(&response).unwrap_or_default()
    )
}

/// Build an STS error response (status code + XML body) from a ProxyError.
pub fn build_sts_error_response(err: &ProxyError) -> (u16, String) {
    let (status, code, message) = match err {
        ProxyError::RoleNotFound(r) => (
            400,
            "MalformedPolicyDocument",
            format!("role not found: {}", r),
        ),
        ProxyError::InvalidOidcToken(msg) => (400, "InvalidIdentityToken", msg.clone()),
        ProxyError::InvalidRequest(msg) => (400, "InvalidParameterValue", msg.clone()),
        ProxyError::AccessDenied => (403, "AccessDenied", "access denied".to_string()),
        // GetCallerIdentity authentication failures.
        ProxyError::SignatureDoesNotMatch => (
            403,
            "SignatureDoesNotMatch",
            "the request signature does not match".to_string(),
        ),
        ProxyError::ExpiredCredentials => (
            403,
            "ExpiredToken",
            "the security token included in the request is expired".to_string(),
        ),
        _ => (500, "InternalError", "internal error".to_string()),
    };

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <ErrorResponse>\
           <Error>\
             <Code>{}</Code>\
             <Message>{}</Message>\
           </Error>\
         </ErrorResponse>",
        code, message
    );
    (status, xml)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn creds() -> TemporaryCredentials {
        TemporaryCredentials {
            access_key_id: "STSPRXYAAA".into(),
            secret_access_key: "secret".into(),
            session_token: "sealed".into(),
            expiration: Utc::now(),
            allowed_scopes: vec![],
            assumed_role_id: "github-actions".into(),
            source_identity: "repo:org/repo:ref:refs/heads/main".into(),
        }
    }

    #[test]
    fn caller_identity_xml_has_account_arn_userid() {
        let xml = build_caller_identity_response(&creds());
        assert!(xml.contains("<Account>000000000000</Account>"), "{xml}");
        assert!(xml.contains(
            "<Arn>arn:aws:sts::000000000000:assumed-role/github-actions/repo:org/repo:ref:refs/heads/main</Arn>"
        ), "{xml}");
        assert!(
            xml.contains("<UserId>github-actions:repo:org/repo:ref:refs/heads/main</UserId>"),
            "{xml}"
        );
    }
}
