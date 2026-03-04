//! Credential exchange — trade a self-signed JWT for cloud provider credentials.

pub mod aws;
#[cfg(feature = "azure")]
pub mod azure;
#[cfg(feature = "gcp")]
pub mod gcp;

use crate::{CloudCredentials, HttpExchange, OidcProviderError};

/// Trait for exchanging a self-signed JWT for cloud provider credentials.
///
/// Each cloud provider has a different token exchange flow:
/// - AWS: `AssumeRoleWithWebIdentity` via STS
/// - Azure: Federated token exchange via Azure AD
/// - GCP: STS token exchange + `generateAccessToken` via IAM
pub trait CredentialExchange<H: HttpExchange>:
    multistore::maybe_send::MaybeSend + multistore::maybe_send::MaybeSync
{
    fn exchange(
        &self,
        http: &H,
        jwt: &str,
    ) -> impl std::future::Future<Output = Result<CloudCredentials, OidcProviderError>>
           + multistore::maybe_send::MaybeSend;
}
