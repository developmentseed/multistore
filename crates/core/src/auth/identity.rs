//! Identity resolution from inbound requests.
//!
//! Parses the SigV4 Authorization header, looks up the credential, verifies
//! the signature, and returns the resolved identity.

use super::sigv4::{constant_time_eq, parse_sigv4_auth, verify_sigv4_signature};
use crate::config::ConfigProvider;
use crate::error::ProxyError;
use crate::sealed_token::TokenKey;
use crate::types::ResolvedIdentity;
use http::HeaderMap;

/// Resolve the identity of an incoming request.
///
/// Parses the SigV4 Authorization header, looks up the credential, verifies
/// the signature, and returns the resolved identity.
pub async fn resolve_identity<C: ConfigProvider>(
    method: &http::Method,
    uri_path: &str,
    query_string: &str,
    headers: &HeaderMap,
    config: &C,
    token_key: Option<&TokenKey>,
) -> Result<ResolvedIdentity, ProxyError> {
    let auth_header = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(h) => h,
        None => return Ok(ResolvedIdentity::Anonymous),
    };

    let sig = parse_sigv4_auth(auth_header)?;

    // The payload hash is sent by the client in x-amz-content-sha256.
    // For streaming uploads this is the UNSIGNED-PAYLOAD or
    // STREAMING-AWS4-HMAC-SHA256-PAYLOAD sentinel — both are valid
    // canonical-request inputs per the SigV4 spec.
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");

    // Temporary credentials: decrypt the session token to recover credentials
    if let Some(session_token) = headers
        .get("x-amz-security-token")
        .and_then(|v| v.to_str().ok())
    {
        let key = token_key.ok_or_else(|| {
            tracing::warn!("session token present but no token_key configured");
            ProxyError::AccessDenied
        })?;

        match key.unseal(session_token)? {
            Some(creds) => {
                if !constant_time_eq(sig.access_key_id.as_bytes(), creds.access_key_id.as_bytes()) {
                    tracing::warn!(
                        header_key = %sig.access_key_id,
                        sealed_key = %creds.access_key_id,
                        "access key mismatch between auth header and sealed token"
                    );
                    return Err(ProxyError::AccessDenied);
                }
                if !verify_sigv4_signature(
                    method,
                    uri_path,
                    query_string,
                    headers,
                    &sig,
                    &creds.secret_access_key,
                    payload_hash,
                )? {
                    return Err(ProxyError::SignatureDoesNotMatch);
                }
                tracing::debug!(
                    access_key = %creds.access_key_id,
                    role = %creds.assumed_role_id,
                    scopes = ?creds.allowed_scopes,
                    "sealed token identity resolved"
                );
                return Ok(ResolvedIdentity::Temporary { credentials: creds });
            }
            None => {
                tracing::warn!(
                    access_key_id = %sig.access_key_id,
                    token_len = session_token.len(),
                    "session token could not be unsealed — possible key mismatch, token corruption, or expired key rotation"
                );
                return Err(ProxyError::AccessDenied);
            }
        }
    }

    // Check long-lived credentials
    if let Some(cred) = config.get_credential(&sig.access_key_id).await? {
        if !cred.enabled {
            return Err(ProxyError::AccessDenied);
        }
        if let Some(expires) = cred.expires_at {
            if expires <= chrono::Utc::now() {
                return Err(ProxyError::ExpiredCredentials);
            }
        }

        // Verify SigV4 signature
        if !verify_sigv4_signature(
            method,
            uri_path,
            query_string,
            headers,
            &sig,
            &cred.secret_access_key,
            payload_hash,
        )? {
            return Err(ProxyError::SignatureDoesNotMatch);
        }

        return Ok(ResolvedIdentity::LongLived { credential: cred });
    }

    Err(ProxyError::AccessDenied)
}
