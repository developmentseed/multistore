//! AWS STS `AssumeRoleWithWebIdentity` credential exchange.
//!
//! This module owns both the runtime-agnostic request/response *mechanism*
//! (build the `AssumeRoleWithWebIdentity` form, parse the XML reply) and the
//! [`AwsExchange`] that drives it over the caller's HTTP transport. The
//! mechanism performs no HTTP itself — multistore deployments differ in their
//! HTTP stack (reqwest on native, `web_sys::fetch` on Cloudflare Workers), so
//! the transport stays with the caller.

use std::borrow::Cow;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use thiserror::Error;

use super::CredentialExchange;
use crate::{BackendCredentials, HttpExchange, OidcProviderError};

/// Configuration for exchanging a JWT for AWS credentials.
#[derive(Debug, Clone)]
pub struct AwsExchange {
    /// The ARN of the IAM role to assume (e.g. `arn:aws:iam::123456789012:role/MyRole`).
    pub role_arn: String,

    /// AWS STS endpoint. Defaults to the global endpoint.
    pub sts_endpoint: String,

    /// Session name included in the assumed role credentials.
    pub session_name: String,

    /// Requested credential lifetime, in seconds. `None` lets AWS apply the
    /// role's default (3600s); otherwise AWS clamps to the role's maximum.
    pub duration_seconds: Option<u32>,

    /// Optional inline session policy (JSON) that further restricts the session.
    pub session_policy: Option<String>,
}

impl Default for AwsExchange {
    fn default() -> Self {
        Self {
            role_arn: String::new(),
            sts_endpoint: "https://sts.amazonaws.com".into(),
            session_name: "s3-proxy".into(),
            duration_seconds: None,
            session_policy: None,
        }
    }
}

impl AwsExchange {
    /// Create an exchange targeting the given IAM role ARN, using default STS endpoint and session name.
    pub fn new(role_arn: String) -> Self {
        Self {
            role_arn,
            ..Default::default()
        }
    }

    /// Override the STS endpoint (e.g. for regional or FIPS endpoints).
    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.sts_endpoint = endpoint;
        self
    }

    /// Override the session name embedded in the assumed-role credentials.
    pub fn with_session_name(mut self, name: String) -> Self {
        self.session_name = name;
        self
    }

    /// Request a specific credential lifetime (seconds); AWS clamps to the role's max.
    pub fn with_duration(mut self, seconds: u32) -> Self {
        self.duration_seconds = Some(seconds);
        self
    }

    /// Attach an inline session policy (JSON) that further restricts the session.
    pub fn with_session_policy(mut self, policy: String) -> Self {
        self.session_policy = Some(policy);
        self
    }
}

impl<H: HttpExchange> CredentialExchange<H> for AwsExchange {
    async fn exchange(
        &self,
        http: &H,
        jwt: &str,
    ) -> Result<BackendCredentials, OidcProviderError> {
        // Build the request with this module's `AssumeRoleWithWebIdentity`, hand
        // its (unencoded) pairs to the runtime's HTTP client — which
        // form-urlencodes them — then parse the reply.
        let request = AssumeRoleWithWebIdentity {
            role_arn: &self.role_arn,
            web_identity_token: jwt,
            role_session_name: &self.session_name,
            duration_seconds: self.duration_seconds,
            session_policy: self.session_policy.as_deref(),
        };

        let pairs = request.form_pairs();
        let form: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_ref())).collect();

        let body = http.post_form(&self.sts_endpoint, &form).await?;

        Ok(parse_response(&body)?)
    }
}

// ── AWS STS request/response mechanism ──────────────────────────────────────
// Runtime-agnostic: builds the request (URL + form body) and parses the XML
// reply, but performs no HTTP itself — `AwsExchange` (above) owns the transport.

/// Failure modes of parsing an `AssumeRoleWithWebIdentity` reply.
///
/// Mapped to [`OidcProviderError`](crate::OidcProviderError) at the crate root
/// (`Sts` → `StsError`, `Parse` → `ExchangeError`).
#[derive(Debug, Error)]
pub(crate) enum FederationError {
    /// The STS endpoint returned an error document instead of credentials.
    ///
    /// The `code`/`message` come straight from the provider (e.g. AWS
    /// `InvalidIdentityToken` / "No OpenIDConnect provider found…") and are the
    /// most useful signal when diagnosing a trust-policy or issuer
    /// misconfiguration.
    #[error("STS returned an error: {code}: {message}")]
    Sts {
        /// Provider error code (e.g. `InvalidIdentityToken`).
        code: String,
        /// Human-readable provider message.
        message: String,
    },

    /// The response could not be parsed as either a success or an error document.
    #[error("failed to parse STS response")]
    Parse(#[from] quick_xml::DeError),
}

/// Parameters for an `AssumeRoleWithWebIdentity` request.
///
/// The web identity token is the OIDC assertion minted by the proxy; the role's
/// trust policy must trust the proxy's issuer and may condition on the token's
/// `aud`/`sub`.
#[derive(Debug, Clone)]
pub(crate) struct AssumeRoleWithWebIdentity<'a> {
    /// ARN of the role to assume.
    pub role_arn: &'a str,
    /// The OIDC token presented as the web identity.
    pub web_identity_token: &'a str,
    /// Session name recorded in CloudTrail for this assumption.
    pub role_session_name: &'a str,
    /// Requested credential lifetime, in seconds. `None` omits `DurationSeconds`
    /// so AWS applies the role's default (3600s); when set, AWS clamps to the
    /// role's maximum and rejects values below 900.
    pub duration_seconds: Option<u32>,
    /// Optional inline session policy (further restricts the session, e.g. to a
    /// key prefix) — `None` to use the role's permissions as-is.
    pub session_policy: Option<&'a str>,
}

impl<'a> AssumeRoleWithWebIdentity<'a> {
    /// The request as form key/value pairs, with values **unencoded**.
    ///
    /// Use this when the HTTP layer performs its own form-urlencoding (e.g.
    /// reqwest's `.form(...)`); feeding it a pre-encoded [`body`](Self::body)
    /// instead would double-encode the values.
    pub fn form_pairs(&self) -> Vec<(&'static str, Cow<'a, str>)> {
        let mut pairs = vec![
            ("Action", Cow::Borrowed("AssumeRoleWithWebIdentity")),
            ("Version", Cow::Borrowed("2011-06-15")),
            ("RoleArn", Cow::Borrowed(self.role_arn)),
            ("RoleSessionName", Cow::Borrowed(self.role_session_name)),
            ("WebIdentityToken", Cow::Borrowed(self.web_identity_token)),
        ];
        if let Some(duration) = self.duration_seconds {
            pairs.push(("DurationSeconds", Cow::Owned(duration.to_string())));
        }
        if let Some(policy) = self.session_policy {
            pairs.push(("Policy", Cow::Borrowed(policy)));
        }
        pairs
    }
}

/// Parse the body of an `AssumeRoleWithWebIdentity` response into credentials.
///
/// AWS returns the same XML shape regardless of HTTP status on the error path
/// (an `<ErrorResponse>` document), so this inspects the body rather than
/// relying on the status code: an error document becomes
/// [`FederationError::Sts`] carrying the provider's code and message.
pub(crate) fn parse_response(xml: &str) -> Result<BackendCredentials, FederationError> {
    if xml.contains("<ErrorResponse") {
        let err: ErrorResponse = quick_xml::de::from_str(xml)?;
        return Err(FederationError::Sts {
            code: err.error.code,
            message: err.error.message,
        });
    }

    let resp: AssumeRoleWithWebIdentityResponse = quick_xml::de::from_str(xml)?;
    let creds = resp.result.credentials;
    Ok(BackendCredentials {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration,
    })
}

// ── XML response shapes ─────────────────────────────────────────────────────
// Only the fields we need are declared; serde ignores the rest (AssumedRoleUser,
// Provider, Audience, ResponseMetadata, …).

#[derive(Deserialize)]
struct AssumeRoleWithWebIdentityResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: AssumeRoleWithWebIdentityResult,
}

#[derive(Deserialize)]
struct AssumeRoleWithWebIdentityResult {
    #[serde(rename = "Credentials")]
    credentials: Credentials,
}

#[derive(Deserialize)]
struct Credentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "SessionToken")]
    session_token: String,
    #[serde(rename = "Expiration")]
    expiration: DateTime<Utc>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    #[serde(rename = "Error")]
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUCCESS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>scv1:conn:test</SubjectFromWebIdentityToken>
    <Audience>source-coop-data-proxy</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/my-role/multistore</Arn>
      <AssumedRoleId>AROAEXAMPLE:multistore</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secret/+key</SecretAccessKey>
      <SessionToken>sess+tok/en==</SessionToken>
      <Expiration>2026-06-03T04:13:40Z</Expiration>
    </Credentials>
    <Provider>https://data.source.coop</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>11111111-2222-3333-4444-555555555555</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>"#;

    const ERROR: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidIdentityToken</Code>
    <Message>No OpenIDConnect provider found in your account for https://data.source.coop</Message>
  </Error>
  <RequestId>aaaa</RequestId>
</ErrorResponse>"#;

    #[test]
    fn parses_credentials() {
        let creds = parse_response(SUCCESS).expect("should parse");
        assert_eq!(creds.access_key_id, "ASIAEXAMPLE");
        assert_eq!(creds.secret_access_key, "secret/+key");
        assert_eq!(creds.session_token, "sess+tok/en==");
        assert_eq!(creds.expiration.to_rfc3339(), "2026-06-03T04:13:40+00:00");
    }

    #[test]
    fn surfaces_sts_error_as_typed_error() {
        match parse_response(ERROR) {
            Err(FederationError::Sts { code, message }) => {
                assert_eq!(code, "InvalidIdentityToken");
                assert!(message.contains("No OpenIDConnect provider"));
            }
            other => panic!("expected Sts error, got {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        let creds = parse_response(SUCCESS).unwrap();
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("ASIAEXAMPLE"));
        assert!(!dbg.contains("secret/+key"));
        assert!(!dbg.contains("sess+tok/en"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn form_pairs_includes_duration_and_policy_when_set() {
        let req = AssumeRoleWithWebIdentity {
            role_arn: "arn:aws:iam::1:role/r",
            web_identity_token: "t",
            role_session_name: "s",
            duration_seconds: Some(900),
            session_policy: Some("{\"Version\":\"2012-10-17\"}"),
        };
        let pairs = req.form_pairs();
        assert!(pairs
            .iter()
            .any(|(k, v)| *k == "DurationSeconds" && v.as_ref() == "900"));
        assert!(pairs.iter().any(|(k, _)| *k == "Policy"));
    }

    #[test]
    fn form_pairs_omit_duration_and_policy_when_unset() {
        let req = AssumeRoleWithWebIdentity {
            role_arn: "arn:aws:iam::1:role/r",
            web_identity_token: "t",
            role_session_name: "s",
            duration_seconds: None,
            session_policy: None,
        };
        let pairs = req.form_pairs();
        assert!(pairs.iter().all(|(k, _)| *k != "DurationSeconds"));
        assert!(pairs.iter().all(|(k, _)| *k != "Policy"));
    }

    #[test]
    fn form_pairs_are_unencoded() {
        let req = AssumeRoleWithWebIdentity {
            role_arn: "arn:aws:iam::123456789012:role/my-role",
            web_identity_token: "tok",
            role_session_name: "multistore",
            duration_seconds: Some(3600),
            session_policy: None,
        };
        let pairs = req.form_pairs();
        // Values are raw (the caller's HTTP layer encodes them) — note the `:`/`/`
        // are NOT percent-encoded here, unlike in `body()`.
        assert!(pairs.iter().any(
            |(k, v)| *k == "RoleArn" && v.as_ref() == "arn:aws:iam::123456789012:role/my-role"
        ));
        assert!(pairs
            .iter()
            .any(|(k, v)| *k == "DurationSeconds" && v.as_ref() == "3600"));
        assert!(pairs.iter().all(|(k, _)| *k != "Policy"));
    }
}
