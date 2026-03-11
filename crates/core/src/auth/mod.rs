//! Authentication and authorization.
//!
//! SigV4 verification is handled by the s3s framework. This module provides:
//! - [`authorize`] — check if an identity can perform an S3 operation
//! - [`TemporaryCredentialResolver`] — resolve session tokens into temporary credentials

mod authorize_impl;

pub use authorize_impl::authorize;

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
