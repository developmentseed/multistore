//! Credential registry trait for looking up authentication data.

use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::types::{RoleConfig, StoredCredential};
use std::future::Future;

/// Trait for retrieving credentials and roles from a backend store.
///
/// Implementations should be cheap to clone (wrap inner state in `Arc`).
///
/// Temporary credentials are resolved via a [`TemporaryCredentialResolver`](crate::auth::TemporaryCredentialResolver)
/// rather than stored here.
pub trait CredentialRegistry: Clone + MaybeSend + MaybeSync + 'static {
    /// Look up a long-lived credential by its access key ID.
    fn get_credential(
        &self,
        access_key_id: &str,
    ) -> impl Future<Output = Result<Option<StoredCredential>, ProxyError>> + MaybeSend;

    /// Look up a role by its identifier.
    fn get_role(
        &self,
        role_id: &str,
    ) -> impl Future<Output = Result<Option<RoleConfig>, ProxyError>> + MaybeSend;
}
