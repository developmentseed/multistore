//! AWS STS `AssumeRoleWithWebIdentity` federation.
//!
//! This module is **runtime-agnostic**: it builds the request (URL + form body)
//! and parses the XML response, but does not perform the HTTP call itself.
//! Multistore deployments differ in their HTTP stack (reqwest on native,
//! `web_sys::fetch` on Cloudflare Workers), so the caller owns the transport.
//!
//! ```
//! use multistore_backend_federation::aws::{AssumeRoleWithWebIdentity, parse_response};
//!
//! let req = AssumeRoleWithWebIdentity {
//!     role_arn: "arn:aws:iam::123456789012:role/my-role",
//!     web_identity_token: "<oidc-jwt>",
//!     role_session_name: "multistore",
//!     duration_seconds: Some(3600),
//!     session_policy: None,
//! };
//! assert!(req.body().contains("Action=AssumeRoleWithWebIdentity"));
//!
//! let url = AssumeRoleWithWebIdentity::endpoint("us-east-1");
//! assert_eq!(url, "https://sts.us-east-1.amazonaws.com/");
//!
//! // POST `req.body()` (or `req.form_pairs()` if your HTTP client urlencodes
//! // for you) to `url` as application/x-www-form-urlencoded, then parse the reply:
//! let response_xml = r#"
//!     <AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>
//!       <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
//!       <SecretAccessKey>secret</SecretAccessKey>
//!       <SessionToken>token</SessionToken>
//!       <Expiration>2030-01-01T00:00:00Z</Expiration>
//!     </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"#;
//! let creds = parse_response(response_xml)?;
//! assert_eq!(creds.access_key_id, "ASIAEXAMPLE");
//! # Ok::<(), multistore_backend_federation::FederationError>(())
//! ```

use crate::credentials::FederatedCredentials;
use crate::error::FederationError;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::borrow::Cow;

/// Parameters for an `AssumeRoleWithWebIdentity` request.
///
/// The web identity token is the OIDC assertion minted by the proxy (e.g. via
/// `multistore-oidc-provider`); the role's trust policy must trust the proxy's
/// issuer and may condition on the token's `aud`/`sub`.
#[derive(Debug, Clone)]
pub struct AssumeRoleWithWebIdentity<'a> {
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
    /// The regional STS endpoint URL to POST to.
    ///
    /// Regional endpoints are preferred over the global one; for non-standard
    /// partitions (GovCloud, China) build the URL yourself.
    pub fn endpoint(region: &str) -> String {
        format!("https://sts.{region}.amazonaws.com/")
    }

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

    /// The `application/x-www-form-urlencoded` request body.
    ///
    /// Use this when the HTTP layer sends a raw body; for a layer that encodes
    /// form pairs itself, use [`form_pairs`](Self::form_pairs) to avoid
    /// double-encoding.
    pub fn body(&self) -> String {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in self.form_pairs() {
            form.append_pair(key, &value);
        }
        form.finish()
    }
}

/// Parse the body of an `AssumeRoleWithWebIdentity` response into credentials.
///
/// AWS returns the same XML shape regardless of HTTP status on the error path
/// (an `<ErrorResponse>` document), so this inspects the body rather than
/// relying on the status code: an error document becomes
/// [`FederationError::Sts`] carrying the provider's code and message.
pub fn parse_response(xml: &str) -> Result<FederatedCredentials, FederationError> {
    if xml.contains("<ErrorResponse") {
        let err: ErrorResponse = quick_xml::de::from_str(xml)?;
        return Err(FederationError::Sts {
            code: err.error.code,
            message: err.error.message,
        });
    }

    let resp: AssumeRoleWithWebIdentityResponse = quick_xml::de::from_str(xml)?;
    let creds = resp.result.credentials;
    Ok(FederatedCredentials {
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
    fn body_contains_expected_params() {
        let req = AssumeRoleWithWebIdentity {
            role_arn: "arn:aws:iam::123456789012:role/my-role",
            web_identity_token: "tok.tok.tok",
            role_session_name: "multistore",
            duration_seconds: Some(3600),
            session_policy: None,
        };
        let body = req.body();
        assert!(body.contains("Action=AssumeRoleWithWebIdentity"));
        assert!(body.contains("Version=2011-06-15"));
        assert!(body.contains("DurationSeconds=3600"));
        // RoleArn is percent-encoded (`:` and `/`).
        assert!(body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fmy-role"));
        assert!(body.contains("WebIdentityToken=tok.tok.tok"));
        assert!(!body.contains("Policy="));
    }

    #[test]
    fn body_omits_duration_when_none() {
        let req = AssumeRoleWithWebIdentity {
            role_arn: "arn:aws:iam::1:role/r",
            web_identity_token: "t",
            role_session_name: "s",
            duration_seconds: None,
            session_policy: None,
        };
        assert!(!req.body().contains("DurationSeconds"));
    }

    #[test]
    fn body_includes_session_policy_when_present() {
        let req = AssumeRoleWithWebIdentity {
            role_arn: "arn:aws:iam::1:role/r",
            web_identity_token: "t",
            role_session_name: "s",
            duration_seconds: Some(900),
            session_policy: Some("{\"Version\":\"2012-10-17\"}"),
        };
        assert!(req.body().contains("Policy="));
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

    #[test]
    fn endpoint_is_regional() {
        assert_eq!(
            AssumeRoleWithWebIdentity::endpoint("us-west-2"),
            "https://sts.us-west-2.amazonaws.com/"
        );
    }
}
