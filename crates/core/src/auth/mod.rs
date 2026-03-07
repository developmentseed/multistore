//! Authentication and authorization.
//!
//! - [`sigv4`] — SigV4 request parsing and signature verification
//! - [`identity`] — identity resolution (mapping access key → principal)
//! - [`authorize`](self::authorize::authorize) — authorization (scope checking)
//! - [`TemporaryCredentialResolver`] — trait for resolving session tokens into temporary credentials

mod authorize;
pub mod identity;
pub mod sigv4;

pub use authorize::authorize;
pub use identity::resolve_identity;
pub use sigv4::{parse_sigv4_auth, verify_sigv4_signature, SigV4Auth};

use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::types::TemporaryCredentials;

/// Resolves a session token (from `x-amz-security-token`) into temporary credentials.
///
/// Implementations handle token decryption/lookup. The core proxy calls this
/// during identity resolution without knowing the token format.
pub trait TemporaryCredentialResolver: MaybeSend + MaybeSync {
    fn resolve(&self, token: &str) -> Result<Option<TemporaryCredentials>, ProxyError>;
}

#[cfg(test)]
mod tests;
