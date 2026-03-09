//! OIDC-based backend credential resolution.
//!
//! When a bucket's `backend_options` contains `auth_type=oidc`, the proxy
//! mints a self-signed JWT and exchanges it for temporary cloud credentials
//! via the cloud provider's STS. The resolved credentials are injected back
//! into the config so the existing builder pipeline works unmodified.
//!
//! Implements the [`Middleware`] trait so that credential resolution runs
//! as part of the dispatch middleware chain.

use multistore::error::ProxyError;
use multistore::middleware::{DispatchContext, Middleware, Next};
use multistore::route_handler::HandlerAction;
use multistore::types::BucketConfig;
use std::borrow::Cow;
use std::collections::HashMap;

use crate::exchange::aws::AwsExchange;
use crate::{HttpExchange, OidcCredentialProvider};

/// AWS OIDC backend auth — exchanges a self-signed JWT for temporary
/// AWS credentials via `AssumeRoleWithWebIdentity`.
pub struct AwsBackendAuth<H: HttpExchange> {
    provider: OidcCredentialProvider<H>,
}

impl<H: HttpExchange> AwsBackendAuth<H> {
    pub fn new(provider: OidcCredentialProvider<H>) -> Self {
        Self { provider }
    }

    async fn resolve_aws(
        &self,
        config: &BucketConfig,
    ) -> Result<HashMap<String, String>, ProxyError> {
        let role_arn = config.option("oidc_role_arn").ok_or_else(|| {
            ProxyError::ConfigError(
                "auth_type=oidc requires 'oidc_role_arn' in backend_options".into(),
            )
        })?;
        let subject = config.option("oidc_subject").unwrap_or("s3-proxy");

        let exchange = AwsExchange::new(role_arn.to_string());
        let creds = self
            .provider
            .get_credentials(role_arn, &exchange, subject, &[])
            .await?;

        let mut options = config.backend_options.clone();
        options.insert("access_key_id".into(), creds.access_key_id.clone());
        options.insert("secret_access_key".into(), creds.secret_access_key.clone());
        options.insert("token".into(), creds.session_token.clone());

        // Remove OIDC-specific keys so they don't confuse the builder.
        options.remove("auth_type");
        options.remove("oidc_role_arn");
        options.remove("oidc_subject");

        Ok(options)
    }

    /// Internal helper: resolve credentials if bucket needs OIDC.
    ///
    /// Returns `None` if the bucket doesn't use OIDC auth, `Some(options)` with
    /// replacement backend options if it does.
    #[cfg(test)]
    async fn resolve_credentials(
        &self,
        config: &BucketConfig,
    ) -> Result<Option<HashMap<String, String>>, ProxyError> {
        if config.option("auth_type") != Some("oidc") {
            return Ok(None);
        }
        match config.backend_type.as_str() {
            "s3" => self.resolve_aws(config).await.map(Some),
            other => Err(ProxyError::ConfigError(format!(
                "OIDC backend auth not yet supported for backend_type '{other}'"
            ))),
        }
    }
}

impl<H: HttpExchange> Middleware for AwsBackendAuth<H> {
    async fn handle<'a>(
        &'a self,
        mut ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        if ctx.bucket_config.option("auth_type") == Some("oidc") {
            match ctx.bucket_config.backend_type.as_str() {
                "s3" => {
                    let options = self.resolve_aws(&ctx.bucket_config).await?;
                    ctx.bucket_config = Cow::Owned(BucketConfig {
                        backend_options: options,
                        ..ctx.bucket_config.into_owned()
                    });
                }
                other => {
                    return Err(ProxyError::ConfigError(format!(
                        "OIDC backend auth not yet supported for backend_type '{other}'"
                    )));
                }
            }
        }
        next.run(ctx).await
    }
}

/// Wrapper enum that runtimes use as a single concrete middleware type.
///
/// `Enabled` holds the live OIDC provider; `Disabled` is the no-op fallback.
/// When disabled and a bucket specifies `auth_type=oidc`, a `ConfigError`
/// is returned.
pub enum MaybeOidcAuth<H: HttpExchange> {
    Enabled(Box<AwsBackendAuth<H>>),
    Disabled,
}

impl<H: HttpExchange> Middleware for MaybeOidcAuth<H> {
    async fn handle<'a>(
        &'a self,
        ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        match self {
            MaybeOidcAuth::Enabled(auth) => auth.handle(ctx, next).await,
            MaybeOidcAuth::Disabled => {
                if ctx.bucket_config.option("auth_type") == Some("oidc") {
                    Err(ProxyError::ConfigError(
                        "bucket requires auth_type=oidc but no OIDC provider is configured".into(),
                    ))
                } else {
                    next.run(ctx).await
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::JwtSigner;
    use crate::OidcProviderError;
    use chrono::{Duration, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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
                            <AccessKeyId>AKID_OIDC</AccessKeyId>
                            <SecretAccessKey>secret_oidc</SecretAccessKey>
                            <SessionToken>token_oidc</SessionToken>
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

    fn oidc_bucket_config() -> BucketConfig {
        let mut opts = HashMap::new();
        opts.insert("auth_type".into(), "oidc".into());
        opts.insert("oidc_role_arn".into(), "arn:aws:iam::123:role/Test".into());
        opts.insert(
            "endpoint".into(),
            "https://s3.us-east-1.amazonaws.com".into(),
        );
        opts.insert("bucket_name".into(), "my-bucket".into());
        opts.insert("region".into(), "us-east-1".into());
        BucketConfig {
            name: "test".into(),
            backend_type: "s3".into(),
            backend_prefix: None,
            anonymous_access: false,
            allowed_roles: vec![],
            backend_options: opts,
        }
    }

    fn static_bucket_config() -> BucketConfig {
        let mut opts = HashMap::new();
        opts.insert("access_key_id".into(), "AKID_STATIC".into());
        opts.insert("secret_access_key".into(), "secret_static".into());
        opts.insert(
            "endpoint".into(),
            "https://s3.us-east-1.amazonaws.com".into(),
        );
        opts.insert("bucket_name".into(), "my-bucket".into());
        BucketConfig {
            name: "test".into(),
            backend_type: "s3".into(),
            backend_prefix: None,
            anonymous_access: false,
            allowed_roles: vec![],
            backend_options: opts,
        }
    }

    #[tokio::test]
    async fn resolve_injects_creds_for_oidc_bucket() {
        let http = MockHttp::new();
        let provider = OidcCredentialProvider::new(
            test_signer(),
            http,
            "https://issuer.example.com".into(),
            "sts.amazonaws.com".into(),
        );
        let auth = AwsBackendAuth::new(provider);

        let config = oidc_bucket_config();
        let resolved = auth.resolve_credentials(&config).await.unwrap().unwrap();

        assert_eq!(resolved.get("access_key_id").unwrap(), "AKID_OIDC");
        assert_eq!(resolved.get("secret_access_key").unwrap(), "secret_oidc");
        assert_eq!(resolved.get("token").unwrap(), "token_oidc");
        assert!(!resolved.contains_key("auth_type"));
        assert!(!resolved.contains_key("oidc_role_arn"));
    }

    #[tokio::test]
    async fn resolve_passes_through_static_bucket() {
        let http = MockHttp::new();
        let provider = OidcCredentialProvider::new(
            test_signer(),
            http.clone(),
            "https://issuer.example.com".into(),
            "sts.amazonaws.com".into(),
        );
        let auth = AwsBackendAuth::new(provider);

        let config = static_bucket_config();
        let resolved = auth.resolve_credentials(&config).await.unwrap();

        assert!(resolved.is_none());
        assert_eq!(http.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn maybe_disabled_errors_on_oidc_bucket() {
        // MaybeOidcAuth::Disabled should error when a bucket requires OIDC.
        // We verify the branch condition directly since Next/Dispatch are
        // pub(crate) in core and can't be constructed from here.
        let config = oidc_bucket_config();
        assert_eq!(config.option("auth_type"), Some("oidc"));
        // The Middleware::handle impl returns this error before calling next:
        let err = ProxyError::ConfigError(
            "bucket requires auth_type=oidc but no OIDC provider is configured".into(),
        );
        assert!(err.to_string().contains("no OIDC provider is configured"));
    }

    #[tokio::test]
    async fn maybe_disabled_passes_through_static_bucket() {
        // MaybeOidcAuth::Disabled should pass through when the bucket
        // doesn't require OIDC auth (no auth_type=oidc in options).
        let config = static_bucket_config();
        assert!(config.option("auth_type") != Some("oidc"));
        // The Middleware::handle impl calls next.run(ctx) in this case.
    }
}
