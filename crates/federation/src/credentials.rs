//! Short-lived credentials obtained by federating into a backend cloud, and
//! the glue that injects them into a [`BucketConfig`].

use chrono::{DateTime, Utc};
use multistore::types::BucketConfig;
use std::fmt;

/// Temporary credentials for a backend object store, obtained by exchanging an
/// OIDC assertion at the backend cloud's STS (e.g. AWS
/// `AssumeRoleWithWebIdentity`).
///
/// These are *backend* credentials — distinct from
/// [`multistore::types::TemporaryCredentials`], which are minted by the proxy's
/// own STS for callers. They carry only what an object-store client needs to
/// sign requests, plus the expiry so a caller can cache and refresh them.
#[derive(Clone)]
pub struct FederatedCredentials {
    /// Temporary access key id (AWS `ASIA…`).
    pub access_key_id: String,
    /// Temporary secret access key.
    pub secret_access_key: String,
    /// Session token that must accompany requests using these credentials.
    pub session_token: String,
    /// When these credentials expire.
    pub expiration: DateTime<Utc>,
}

impl FederatedCredentials {
    /// Inject these credentials into a [`BucketConfig`] so the multistore
    /// backend signs requests with them instead of going anonymous.
    ///
    /// Sets the canonical S3 option keys (`access_key_id`, `secret_access_key`,
    /// and `token` — the alias object_store maps to the session token and that
    /// multistore redacts in logs), clears `skip_signature`, and disables
    /// `anonymous_access`.
    pub fn apply_to(&self, config: &mut BucketConfig) {
        let opts = &mut config.backend_options;
        opts.insert("access_key_id".to_string(), self.access_key_id.clone());
        opts.insert(
            "secret_access_key".to_string(),
            self.secret_access_key.clone(),
        );
        opts.insert("token".to_string(), self.session_token.clone());
        opts.remove("skip_signature");
        config.anonymous_access = false;
    }
}

impl fmt::Debug for FederatedCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederatedCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .field("expiration", &self.expiration)
            .finish()
    }
}
