//! Error types for the proxy.

use thiserror::Error;

/// Central error type for the proxy, mapping each variant to an S3-compatible HTTP response.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// The requested virtual bucket does not exist in the registry.
    #[error("bucket not found: {0}")]
    BucketNotFound(String),

    /// The requested object key was not found in the backend store.
    #[error("no such key: {0}")]
    NoSuchKey(String),

    /// The caller's identity lacks permission for the requested operation.
    #[error("access denied")]
    AccessDenied,

    /// The SigV4 signature in the request does not match the expected value.
    #[error("signature mismatch")]
    SignatureDoesNotMatch,

    /// The request is malformed or contains invalid parameters.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The requested S3 operation is recognized but not supported by the proxy
    /// (e.g. server-side copy via `x-amz-copy-source`). Maps to S3's
    /// `501 NotImplemented`.
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// The request contains no authentication credentials.
    #[error("missing authentication")]
    MissingAuth,

    /// The credentials used to sign the request have expired.
    #[error("expired credentials")]
    ExpiredCredentials,

    /// The OIDC token provided for STS role assumption is invalid or untrusted.
    #[error("invalid OIDC token: {0}")]
    InvalidOidcToken(String),

    /// The IAM role specified in an STS request does not exist.
    #[error("role not found: {0}")]
    RoleNotFound(String),

    /// The upstream object store backend returned an error.
    #[error("backend error: {0}")]
    BackendError(String),

    /// The proxy could not obtain credentials from the backend cloud's identity
    /// broker — e.g. AWS STS rejected the proxy's federated identity
    /// (`InvalidIdentityToken`), or the broker was unreachable. Kept distinct
    /// from [`Internal`](Self::Internal) so a federation/trust misconfiguration
    /// surfaces as a diagnosable `502` rather than an opaque `500`. Carries the
    /// provider error *code* only (safe to expose); the full provider message —
    /// which may contain role ARNs / account IDs — is logged at the conversion
    /// site, not returned to the caller.
    #[error("backend authentication failed: {0}")]
    BackendAuthError(String),

    /// A conditional request header (e.g. `If-Match`) was not satisfied.
    #[error("precondition failed")]
    PreconditionFailed,

    /// The object has not been modified since the time specified by `If-Modified-Since`.
    #[error("not modified")]
    NotModified,

    /// The proxy configuration is invalid or incomplete.
    #[error("config error: {0}")]
    ConfigError(String),

    /// An unexpected internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ProxyError {
    /// Return the S3-compatible XML error code.
    pub fn s3_error_code(&self) -> &'static str {
        match self {
            Self::BucketNotFound(_) => "NoSuchBucket",
            Self::NoSuchKey(_) => "NoSuchKey",
            Self::AccessDenied => "AccessDenied",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::InvalidRequest(_) => "InvalidRequest",
            Self::NotImplemented(_) => "NotImplemented",
            Self::MissingAuth => "AccessDenied",
            Self::ExpiredCredentials => "ExpiredToken",
            Self::InvalidOidcToken(_) => "InvalidIdentityToken",
            Self::RoleNotFound(_) => "AccessDenied",
            Self::BackendError(_) => "ServiceUnavailable",
            Self::BackendAuthError(_) => "BackendAuthenticationFailed",
            Self::PreconditionFailed => "PreconditionFailed",
            Self::NotModified => "NotModified",
            Self::ConfigError(_) => "InternalError",
            Self::Internal(_) => "InternalError",
        }
    }

    /// HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::BucketNotFound(_) | Self::NoSuchKey(_) => 404,
            Self::AccessDenied | Self::MissingAuth | Self::ExpiredCredentials => 403,
            Self::SignatureDoesNotMatch => 403,
            Self::InvalidRequest(_) => 400,
            Self::NotImplemented(_) => 501,
            Self::InvalidOidcToken(_) => 400,
            Self::RoleNotFound(_) => 403,
            Self::PreconditionFailed => 412,
            Self::NotModified => 304,
            Self::BackendError(_) => 503,
            Self::BackendAuthError(_) => 502,
            Self::ConfigError(_) | Self::Internal(_) => 500,
        }
    }

    /// Return a message safe to show to external clients.
    ///
    /// For server-side errors (5xx), returns a generic message to avoid
    /// leaking backend infrastructure details. For client errors (4xx),
    /// returns the full message (the client already knows the bucket name,
    /// key, etc.).
    pub fn safe_message(&self) -> String {
        match self {
            Self::BackendError(_) => "Service unavailable".to_string(),
            Self::ConfigError(_) | Self::Internal(_) => "Internal server error".to_string(),
            // Safe to surface: holds only the provider error code (e.g.
            // `InvalidIdentityToken`), never the raw provider message.
            Self::BackendAuthError(code) => {
                format!("Failed to obtain backend credentials: {code}")
            }
            other => other.to_string(),
        }
    }

    /// Convert an `object_store::Error` into a `ProxyError`.
    pub fn from_object_store_error(e: object_store::Error) -> Self {
        match e {
            object_store::Error::NotFound { path, .. } => Self::NoSuchKey(path),
            object_store::Error::Precondition { .. } => Self::PreconditionFailed,
            object_store::Error::NotModified { .. } => Self::NotModified,
            _ => Self::BackendError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_auth_error_is_502_and_not_opaque() {
        let err = ProxyError::BackendAuthError("InvalidIdentityToken".into());
        assert_eq!(err.status_code(), 502);
        assert_eq!(err.s3_error_code(), "BackendAuthenticationFailed");
        // Distinct from the generic internal-error message, and surfaces the
        // provider code so the failure is diagnosable from the response alone.
        let msg = err.safe_message();
        assert_ne!(msg, "Internal server error");
        assert!(msg.contains("InvalidIdentityToken"), "got: {msg}");
    }

    #[test]
    fn internal_error_stays_opaque_5xx() {
        // Genuine internal errors keep the generic message (no detail leak).
        let err = ProxyError::Internal("secret backend detail".into());
        assert_eq!(err.status_code(), 500);
        assert_eq!(err.safe_message(), "Internal server error");
    }
}
