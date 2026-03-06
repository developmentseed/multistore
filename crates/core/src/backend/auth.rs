//! Trait for backend credential resolution.
//!
//! Implementations can resolve credentials however they need to — OIDC token
//! exchange, vault lookups, environment variables, etc. The resolved options
//! replace the bucket's `backend_options` so the existing builder pipeline
//! works unmodified.
//!
//! [`NoAuth`] is the default no-op implementation used when no credential
//! resolver is configured.

use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::types::BucketConfig;
use std::collections::HashMap;
use std::future::Future;

/// Resolves backend credentials before store/signer creation.
///
/// Called at the top of `dispatch_operation()` before the config reaches
/// `create_store()` / `create_signer()`. Returns `None` if no credential
/// resolution is needed, or `Some(options)` with replacement backend options.
pub trait BackendAuth: MaybeSend + MaybeSync + 'static {
    fn resolve_credentials(
        &self,
        config: &BucketConfig,
    ) -> impl Future<Output = Result<Option<HashMap<String, String>>, ProxyError>> + MaybeSend;
}

/// No-op implementation — returns `None` (no credential changes).
///
/// If a bucket specifies `auth_type=oidc` but no auth provider is
/// configured, this returns a `ConfigError`.
pub struct NoAuth;

impl BackendAuth for NoAuth {
    async fn resolve_credentials(
        &self,
        config: &BucketConfig,
    ) -> Result<Option<HashMap<String, String>>, ProxyError> {
        if config.option("auth_type") == Some("oidc") {
            return Err(ProxyError::ConfigError(
                "bucket requires auth_type=oidc but no OIDC provider is configured".into(),
            ));
        }
        Ok(None)
    }
}
