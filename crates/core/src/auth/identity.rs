//! Identity resolution from inbound requests.
//!
//! Parses SigV4 material from either the `Authorization` header or a presigned
//! URL's query string, looks up the credential, verifies the signature, and
//! returns the resolved identity. Everything after parsing is shared between
//! the two request shapes.

use super::sigv4::{
    constant_time_eq, is_presigned, parse_sigv4_auth, parse_sigv4_presigned,
    verify_sigv4_presigned, verify_sigv4_signature, SigV4Auth,
};
use super::TemporaryCredentialResolver;
use crate::error::ProxyError;
use crate::registry::CredentialRegistry;
use crate::types::{AuthenticatedIdentity, ResolvedIdentity};
use http::HeaderMap;

/// How the request carried its SigV4 material, plus the mode-specific inputs to
/// signature verification.
enum SigMode {
    /// `Authorization` header. Payload hash comes from `x-amz-content-sha256`.
    Header { payload_hash: String },
    /// Presigned query string. Date comes from the `X-Amz-Date` query param;
    /// payload hash is always `UNSIGNED-PAYLOAD`.
    Presigned { amz_date: String },
}

/// Resolve the identity of an incoming request.
///
/// Authenticates SigV4 requests signed via the `Authorization` header or via a
/// presigned URL (query-string auth). Unsigned requests resolve to
/// [`ResolvedIdentity::Anonymous`].
pub async fn resolve_identity<C: CredentialRegistry>(
    method: &http::Method,
    uri_path: &str,
    query_string: &str,
    headers: &HeaderMap,
    config: &C,
    credential_resolver: Option<&dyn TemporaryCredentialResolver>,
) -> Result<ResolvedIdentity, ProxyError> {
    // Parse SigV4 material from the header or, failing that, a presigned query.
    // The tail below (resolve → verify → Authenticated) is mode-agnostic.
    let (sig, mode, session_token): (SigV4Auth, SigMode, Option<String>) =
        if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            let sig = parse_sigv4_auth(auth_header)?;
            // For streaming uploads the payload hash is the UNSIGNED-PAYLOAD or
            // STREAMING-AWS4-HMAC-SHA256-PAYLOAD sentinel — both are valid
            // canonical-request inputs per the SigV4 spec.
            let payload_hash = headers
                .get("x-amz-content-sha256")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("UNSIGNED-PAYLOAD")
                .to_string();
            let token = headers
                .get("x-amz-security-token")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            (sig, SigMode::Header { payload_hash }, token)
        } else if is_presigned(query_string) {
            let presigned = parse_sigv4_presigned(query_string)?;
            check_presigned_expiry(&presigned.amz_date, presigned.expires)?;
            (
                presigned.auth,
                SigMode::Presigned {
                    amz_date: presigned.amz_date,
                },
                presigned.session_token,
            )
        } else {
            return Ok(ResolvedIdentity::Anonymous);
        };

    // Verify against a candidate secret, dispatching on how the request was signed.
    let verify = |secret: &str| -> Result<bool, ProxyError> {
        match &mode {
            SigMode::Header { payload_hash } => verify_sigv4_signature(
                method,
                uri_path,
                query_string,
                headers,
                &sig,
                secret,
                payload_hash,
            ),
            SigMode::Presigned { amz_date } => verify_sigv4_presigned(
                method,
                uri_path,
                query_string,
                headers,
                &sig,
                secret,
                amz_date,
            ),
        }
    };

    // Temporary credentials: resolve the session token to recover credentials.
    if let Some(session_token) = session_token.as_deref() {
        let resolver = credential_resolver.ok_or_else(|| {
            tracing::warn!("session token present but no credential resolver configured");
            ProxyError::AccessDenied
        })?;

        match resolver.resolve(session_token)? {
            Some(creds) => {
                if !constant_time_eq(sig.access_key_id.as_bytes(), creds.access_key_id.as_bytes()) {
                    tracing::warn!(
                        request_key = %sig.access_key_id,
                        resolved_key = %creds.access_key_id,
                        "access key mismatch between request and session token"
                    );
                    return Err(ProxyError::AccessDenied);
                }
                if !verify(&creds.secret_access_key)? {
                    return Err(ProxyError::SignatureDoesNotMatch);
                }
                tracing::debug!(
                    access_key = %creds.access_key_id,
                    role = %creds.assumed_role_id,
                    scopes = ?creds.allowed_scopes,
                    "temporary credential identity resolved"
                );
                return Ok(ResolvedIdentity::Authenticated(AuthenticatedIdentity {
                    principal_name: creds.source_identity.clone(),
                    allowed_scopes: creds.allowed_scopes.clone(),
                }));
            }
            None => {
                tracing::warn!(
                    access_key_id = %sig.access_key_id,
                    token_len = session_token.len(),
                    "session token could not be resolved — possible key mismatch, token corruption, or expired key rotation"
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

        if !verify(&cred.secret_access_key)? {
            return Err(ProxyError::SignatureDoesNotMatch);
        }

        return Ok(ResolvedIdentity::Authenticated(AuthenticatedIdentity {
            principal_name: cred.principal_name.clone(),
            allowed_scopes: cred.allowed_scopes,
        }));
    }

    Err(ProxyError::AccessDenied)
}

/// Reject a presigned request whose signing window has elapsed.
///
/// The window is `[X-Amz-Date, X-Amz-Date + X-Amz-Expires]`, with a few seconds
/// of clock-skew tolerance on the trailing edge.
fn check_presigned_expiry(amz_date: &str, expires_secs: u64) -> Result<(), ProxyError> {
    const SKEW: i64 = 5;

    let signed = chrono::NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ")
        .map_err(|_| ProxyError::InvalidRequest("invalid X-Amz-Date".into()))?
        .and_utc();
    let expiry = signed + chrono::Duration::seconds(expires_secs as i64 + SKEW);

    if chrono::Utc::now() > expiry {
        tracing::warn!(%amz_date, expires_secs, "presigned URL expired");
        return Err(ProxyError::ExpiredCredentials);
    }
    Ok(())
}
