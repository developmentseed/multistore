//! OIDC provider for outbound authentication.
//!
//! This crate enables the proxy to act as its own OIDC identity provider:
//!
//! 1. **JWT signing** — mint JWTs signed with the proxy's RSA private key
//! 2. **JWKS serving** — expose the corresponding public key as a JWK set
//! 3. **OIDC discovery** — generate `.well-known/openid-configuration` responses
//! 4. **Credential exchange** — trade self-signed JWTs for cloud provider
//!    credentials (AWS STS, Azure AD, GCP STS)
//! 5. **Route handler** — [`route_handler::OidcRouterExt`] registers
//!    `.well-known` endpoint closures on a [`Router`](multistore::router::Router)
//!
//! The crate is runtime-agnostic: HTTP calls are abstracted behind an
//! [`HttpExchange`] trait so that each runtime (reqwest, Fetch API, etc.)
//! can provide its own implementation.

pub mod backend_auth;
pub mod cache;
pub mod discovery;
pub mod exchange;
pub mod jwks;
pub mod jwt;
pub mod route_handler;

use std::sync::Arc;

use cache::CredentialCache;
use exchange::CredentialExchange;
use jwt::JwtSigner;

/// The backend credential value type — its fields, secret-redacting `Debug`, and
/// `BucketConfig` injection ([`BackendCredentials::apply_to`]) — is owned by
/// `multistore` core (next to the `BucketConfig` it injects into, and its
/// sibling `TemporaryCredentials`). It is re-exported here so this crate is the
/// single front door: callers import the type from `multistore-oidc-provider`
/// and need not name core's `types` module.
///
/// Bearer-only backends (Azure/GCP) leave `access_key_id`/`secret_access_key`
/// empty and carry the token in `session_token`.
pub use multistore::types::BackendCredentials;

/// HTTP client abstraction for outbound requests (STS token exchange).
///
/// Each runtime provides its own implementation — `reqwest` on native,
/// `Fetch` on Cloudflare Workers.
pub trait HttpExchange:
    Clone + multistore::maybe_send::MaybeSend + multistore::maybe_send::MaybeSync + 'static
{
    /// Send a `POST` request with form-encoded body and return the response text.
    fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> impl std::future::Future<Output = Result<String, OidcProviderError>>
           + multistore::maybe_send::MaybeSend;
}

/// Top-level provider that combines signing, exchange, and caching.
pub struct OidcCredentialProvider<H: HttpExchange> {
    signer: JwtSigner,
    cache: CredentialCache,
    http: H,
    issuer: String,
    audience: String,
}

impl<H: HttpExchange> OidcCredentialProvider<H> {
    /// Create a new provider.
    ///
    /// * `signer`   — RSA JWT signer used to mint self-signed tokens.
    /// * `http`     — runtime-specific HTTP client for outbound STS calls.
    /// * `issuer`   — `iss` claim written into minted JWTs (must match OIDC discovery).
    /// * `audience` — `aud` claim written into minted JWTs (must match the cloud provider's expected audience).
    pub fn new(signer: JwtSigner, http: H, issuer: String, audience: String) -> Self {
        Self {
            signer,
            cache: CredentialCache::new(),
            http,
            issuer,
            audience,
        }
    }

    /// Get credentials for a backend, using cached values when available.
    ///
    /// `exchange` describes how to trade the self-signed JWT for cloud
    /// credentials (AWS, Azure, GCP). `cache_key` identifies the backend
    /// for caching purposes (e.g. the role ARN).
    pub async fn get_credentials<E: CredentialExchange<H>>(
        &self,
        cache_key: &str,
        exchange: &E,
        subject: &str,
        extra_claims: &[(&str, &str)],
    ) -> Result<Arc<BackendCredentials>, OidcProviderError> {
        // Check cache first
        if let Some(creds) = self.cache.get(cache_key) {
            return Ok(creds);
        }

        // Mint a JWT
        let token = self
            .signer
            .sign(subject, &self.issuer, &self.audience, extra_claims)?;

        // Exchange it for cloud credentials
        let creds: BackendCredentials = exchange.exchange(&self.http, &token).await?;
        let creds = Arc::new(creds);

        // Cache
        self.cache.put(cache_key.to_string(), creds.clone());

        Ok(creds)
    }

    /// Access the underlying signer (e.g. for JWKS generation).
    pub fn signer(&self) -> &JwtSigner {
        &self.signer
    }
}

/// Errors produced by this crate.
#[derive(Debug, thiserror::Error)]
pub enum OidcProviderError {
    #[error("RSA key error: {0}")]
    KeyError(String),

    #[error("JWT signing error: {0}")]
    SigningError(String),

    #[error("credential exchange failed: {0}")]
    ExchangeError(String),

    /// The backend cloud's STS returned an error document (e.g. AWS
    /// `InvalidIdentityToken`). The `code`/`message` come from the provider and
    /// usually point at a trust-policy or issuer misconfiguration; they are not
    /// sanitized, so do not echo them verbatim to untrusted callers.
    #[error("STS returned an error: {code}: {message}")]
    StsError {
        /// Provider error code (e.g. `InvalidIdentityToken`).
        code: String,
        /// Human-readable provider message.
        message: String,
    },

    #[error("HTTP error: {0}")]
    HttpError(String),
}

impl From<crate::exchange::aws::FederationError> for OidcProviderError {
    fn from(e: crate::exchange::aws::FederationError) -> Self {
        use crate::exchange::aws::FederationError as F;
        match e {
            F::Sts { code, message } => OidcProviderError::StsError { code, message },
            F::Parse(e) => OidcProviderError::ExchangeError(e.to_string()),
        }
    }
}

impl From<OidcProviderError> for multistore::error::ProxyError {
    fn from(e: OidcProviderError) -> Self {
        use multistore::error::ProxyError;

        // Federation failures must not collapse into an opaque 500. Map each
        // cause to a status that reflects whose problem it is, and log the full
        // (possibly ARN-bearing) detail here — it is the only place the raw
        // provider message is still available, and it must not reach the caller.
        match e {
            OidcProviderError::StsError { code, message } => {
                tracing::error!(
                    sts_code = %code,
                    sts_message = %message,
                    "backend STS rejected the federation exchange"
                );
                match code.as_str() {
                    // The role's trust policy / permissions deny the proxy
                    // identity: the object genuinely cannot be served → 403.
                    "AccessDenied" => ProxyError::AccessDenied,
                    // Our minted assertion was rejected (bad key, issuer, or no
                    // registered provider), or any other STS error → 502: the
                    // gateway failed to authenticate to its upstream broker.
                    _ => ProxyError::BackendAuthError(code),
                }
            }
            // Local signing-key problems: the deploy's OIDC_PROVIDER_KEY is
            // missing/malformed. The gateway can't mint an assertion, so it
            // can't federate → 502 (not a generic 500), with the cause logged.
            OidcProviderError::KeyError(detail) => {
                tracing::error!(error = %detail, "OIDC provider RSA key error");
                ProxyError::BackendAuthError("ProviderKeyError".into())
            }
            OidcProviderError::SigningError(detail) => {
                tracing::error!(error = %detail, "OIDC provider JWT signing error");
                ProxyError::BackendAuthError("SigningError".into())
            }
            // Couldn't reach the broker or parse its reply: transient/upstream
            // → 503 (retryable), distinct from a permanent auth rejection.
            OidcProviderError::HttpError(detail) => {
                tracing::error!(error = %detail, "backend STS transport error");
                ProxyError::BackendError(detail)
            }
            OidcProviderError::ExchangeError(detail) => {
                tracing::error!(error = %detail, "backend credential exchange failed");
                ProxyError::BackendError(detail)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock HTTP client that records calls and returns a preset AWS STS response.
    #[derive(Clone)]
    struct MockHttp {
        call_count: Arc<AtomicUsize>,
    }

    impl MockHttp {
        fn new() -> Self {
            Self {
                call_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl HttpExchange for MockHttp {
        async fn post_form(
            &self,
            _url: &str,
            _form: &[(&str, &str)],
        ) -> Result<String, OidcProviderError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let exp = (Utc::now() + Duration::hours(1)).to_rfc3339();
            Ok(format!(
                r#"<AssumeRoleWithWebIdentityResponse>
                    <AssumeRoleWithWebIdentityResult>
                        <Credentials>
                            <AccessKeyId>AKID_MOCK</AccessKeyId>
                            <SecretAccessKey>secret_mock</SecretAccessKey>
                            <SessionToken>token_mock</SessionToken>
                            <Expiration>{exp}</Expiration>
                        </Credentials>
                    </AssumeRoleWithWebIdentityResult>
                </AssumeRoleWithWebIdentityResponse>"#
            ))
        }
    }

    fn test_signer() -> JwtSigner {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rand::rngs::OsRng;
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        JwtSigner::from_pem(&pem, "test-kid".into(), 300).unwrap()
    }

    #[tokio::test]
    async fn get_credentials_returns_fresh_on_first_call() {
        let http = MockHttp::new();
        let provider = OidcCredentialProvider::new(
            test_signer(),
            http.clone(),
            "https://issuer.example.com".into(),
            "sts.amazonaws.com".into(),
        );

        let exchange = exchange::aws::AwsExchange::new("arn:aws:iam::123:role/Test".into());
        let creds = provider
            .get_credentials("role-a", &exchange, "my-sub", &[])
            .await
            .unwrap();

        assert_eq!(creds.access_key_id, "AKID_MOCK");
        assert_eq!(http.calls(), 1);
    }

    #[tokio::test]
    async fn get_credentials_uses_cache_on_second_call() {
        let http = MockHttp::new();
        let provider = OidcCredentialProvider::new(
            test_signer(),
            http.clone(),
            "https://issuer.example.com".into(),
            "sts.amazonaws.com".into(),
        );

        let exchange = exchange::aws::AwsExchange::new("arn:aws:iam::123:role/Test".into());

        // First call — hits mock HTTP
        let creds1 = provider
            .get_credentials("role-a", &exchange, "sub", &[])
            .await
            .unwrap();
        assert_eq!(http.calls(), 1);

        // Second call — should use cache, no additional HTTP call
        let creds2 = provider
            .get_credentials("role-a", &exchange, "sub", &[])
            .await
            .unwrap();
        assert_eq!(http.calls(), 1);
        assert_eq!(creds1.access_key_id, creds2.access_key_id);
    }

    #[tokio::test]
    async fn different_cache_keys_make_separate_calls() {
        let http = MockHttp::new();
        let provider = OidcCredentialProvider::new(
            test_signer(),
            http.clone(),
            "https://issuer.example.com".into(),
            "sts.amazonaws.com".into(),
        );

        let exchange = exchange::aws::AwsExchange::new("arn:aws:iam::123:role/Test".into());

        provider
            .get_credentials("role-a", &exchange, "sub", &[])
            .await
            .unwrap();
        provider
            .get_credentials("role-b", &exchange, "sub", &[])
            .await
            .unwrap();

        assert_eq!(http.calls(), 2);
    }

    #[test]
    fn signed_jwt_is_verifiable_via_jwks_public_key() {
        use base64::Engine;
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;
        use rsa::{BigUint, RsaPublicKey};

        let signer = test_signer();

        // Sign a JWT
        let token = signer.sign("sub", "iss", "aud", &[]).unwrap();

        // Generate JWKS from the same signer
        let jwks_str = jwks::jwks_json(&[(signer.public_key(), signer.kid())]);
        let jwks: serde_json::Value = serde_json::from_str(&jwks_str).unwrap();

        // Extract public key from JWKS
        let key = &jwks["keys"][0];
        let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let n = BigUint::from_bytes_be(&b64.decode(key["n"].as_str().unwrap()).unwrap());
        let e = BigUint::from_bytes_be(&b64.decode(key["e"].as_str().unwrap()).unwrap());
        let reconstructed_key = RsaPublicKey::new(n, e).unwrap();

        // Verify signature using the JWKS-derived key
        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = b64.decode(parts[2]).unwrap();
        let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();

        let verifying_key = VerifyingKey::<sha2::Sha256>::new(reconstructed_key);
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("JWT signed by JwtSigner should be verifiable via JWKS public key");
    }

    #[test]
    fn exchange_error_maps_to_retryable_503() {
        // Transport / unparseable-response failures are upstream and retryable.
        let proxy_err: multistore::error::ProxyError =
            OidcProviderError::ExchangeError("boom".into()).into();
        assert_eq!(proxy_err.status_code(), 503);
        assert!(proxy_err.to_string().contains("boom"));
    }

    #[test]
    fn http_error_maps_to_retryable_503() {
        let proxy_err: multistore::error::ProxyError =
            OidcProviderError::HttpError("connreset".into()).into();
        assert_eq!(proxy_err.status_code(), 503);
    }

    #[test]
    fn sts_rejection_maps_to_502_not_500() {
        // The headline regression: a rejected federation assertion must surface
        // as a diagnosable 502, never an opaque 500 InternalError.
        let proxy_err: multistore::error::ProxyError = OidcProviderError::StsError {
            code: "InvalidIdentityToken".into(),
            message: "No OpenIDConnect provider found in your account".into(),
        }
        .into();
        assert_eq!(proxy_err.status_code(), 502);
        assert_eq!(proxy_err.s3_error_code(), "BackendAuthenticationFailed");
        // The provider *code* is surfaced; the raw message is not.
        let safe = proxy_err.safe_message();
        assert!(safe.contains("InvalidIdentityToken"), "got: {safe}");
        assert!(
            !safe.contains("your account"),
            "raw STS message leaked: {safe}"
        );
    }

    #[test]
    fn sts_access_denied_maps_to_403() {
        // A trust-policy/permissions denial is a real authorization result.
        let proxy_err: multistore::error::ProxyError = OidcProviderError::StsError {
            code: "AccessDenied".into(),
            message: "not authorized to perform sts:AssumeRoleWithWebIdentity".into(),
        }
        .into();
        assert_eq!(proxy_err.status_code(), 403);
        assert_eq!(proxy_err.s3_error_code(), "AccessDenied");
    }

    #[test]
    fn key_and_signing_errors_map_to_502_not_500() {
        // A bad OIDC_PROVIDER_KEY means we can't mint an assertion → 502, logged.
        let key_err: multistore::error::ProxyError =
            OidcProviderError::KeyError("bad pem".into()).into();
        assert_eq!(key_err.status_code(), 502);

        let sign_err: multistore::error::ProxyError =
            OidcProviderError::SigningError("rsa failure".into()).into();
        assert_eq!(sign_err.status_code(), 502);
    }
}
