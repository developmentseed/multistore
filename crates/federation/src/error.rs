//! Errors produced while federating into a backend cloud's STS.

use thiserror::Error;

/// Failure modes of an outbound federation exchange.
#[derive(Debug, Error)]
pub enum FederationError {
    /// The STS endpoint returned an error document instead of credentials.
    ///
    /// The `code`/`message` come straight from the provider (e.g. AWS
    /// `InvalidIdentityToken` / "No OpenIDConnect provider found…") and are
    /// the most useful signal when diagnosing a trust-policy or issuer
    /// misconfiguration.
    #[error("STS returned an error: {code}: {message}")]
    Sts {
        /// Provider error code (e.g. `InvalidIdentityToken`).
        code: String,
        /// Human-readable provider message.
        message: String,
    },

    /// The response could not be parsed as either a success or an error
    /// document.
    #[error("failed to parse STS response: {0}")]
    Parse(String),
}
