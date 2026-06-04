//! AWS STS `AssumeRoleWithWebIdentity` credential exchange.

use crate::{FederatedCredentials, HttpExchange, OidcProviderError};

use super::CredentialExchange;
use multistore_backend_federation::aws::{parse_response, AssumeRoleWithWebIdentity};

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
    ) -> Result<FederatedCredentials, OidcProviderError> {
        // Build the request with the canonical `multistore-backend-federation`
        // primitive, hand its (unencoded) pairs to the runtime's HTTP client —
        // which form-urlencodes them — then parse the reply with the same crate.
        // The parsed `FederatedCredentials` flow through unchanged: this crate no
        // longer keeps a second credential type to convert into.
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
