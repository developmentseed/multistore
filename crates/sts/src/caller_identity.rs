//! `GetCallerIdentity` handling.
//!
//! Standard AWS tooling validates the credentials it obtains from
//! `AssumeRoleWithWebIdentity` by immediately issuing a SigV4-signed
//! `GetCallerIdentity` call against the same endpoint —
//! `aws-actions/configure-aws-credentials` does this unconditionally, with no
//! opt-out. For the proxy to be a drop-in STS target this call must succeed, so
//! this module authenticates it against the sealed-token credentials and
//! returns an STS-shaped identity document.
//!
//! Unlike `AssumeRoleWithWebIdentity` (an unauthenticated token exchange),
//! `GetCallerIdentity` is authenticated: the temporary session token travels in
//! `x-amz-security-token` and the request is SigV4-signed with the temporary
//! secret key. Verification reuses the proxy's own SigV4 machinery, so an
//! assumed-role session proves itself here exactly as it would when signing an
//! S3 request.

use multistore::auth::{parse_sigv4_auth, verify_sigv4_signature};
use multistore::error::ProxyError;
use multistore::route_handler::RequestInfo;
use sha2::{Digest, Sha256};

use crate::responses::{build_caller_identity_response, build_sts_error_response};
use crate::TokenKey;

/// Authenticate a `GetCallerIdentity` request and return `(status, xml)`.
///
/// Success yields `(200, <GetCallerIdentityResponse>)`; any authentication
/// failure yields STS-shaped error XML (never a proxy error), so unsigned or
/// mis-signed callers see a well-formed STS error just as real STS would.
pub fn handle_get_caller_identity(
    req: &RequestInfo<'_>,
    token_key: Option<&TokenKey>,
) -> (u16, String) {
    match resolve_caller_identity(req, token_key) {
        Ok(xml) => (200, xml),
        Err(e) => {
            tracing::warn!(error = %e, "GetCallerIdentity request rejected");
            build_sts_error_response(&e)
        }
    }
}

fn resolve_caller_identity(
    req: &RequestInfo<'_>,
    token_key: Option<&TokenKey>,
) -> Result<String, ProxyError> {
    let token_key = token_key.ok_or_else(|| {
        tracing::error!("GetCallerIdentity received but SESSION_TOKEN_KEY is not configured");
        ProxyError::ConfigError("STS requires SESSION_TOKEN_KEY to be configured".into())
    })?;

    // Recover the minted credentials from the session token, then confirm the
    // request was signed with the matching secret key.
    let session_token = header(req, "x-amz-security-token").ok_or(ProxyError::AccessDenied)?;
    let creds = token_key
        .unseal(session_token)?
        .ok_or(ProxyError::AccessDenied)?;

    let auth_header = header(req, "authorization").ok_or(ProxyError::AccessDenied)?;
    let sig = parse_sigv4_auth(auth_header)?;
    if sig.access_key_id != creds.access_key_id {
        tracing::warn!(
            header_key = %sig.access_key_id,
            resolved_key = %creds.access_key_id,
            "access key mismatch between auth header and session token"
        );
        return Err(ProxyError::AccessDenied);
    }

    // AWS SDKs sign an STS POST over the SHA-256 of its form body. They usually
    // also echo that digest in x-amz-content-sha256; honor the header when
    // present, otherwise recompute it from the body the runtime collected.
    let body = req.form_body.unwrap_or_default();
    let payload_hash = header(req, "x-amz-content-sha256")
        .map(str::to_owned)
        .unwrap_or_else(|| hex::encode(Sha256::digest(body.as_bytes())));

    // Verify over the raw path/query the client actually signed. AWS SDK JS v3
    // (used by configure-aws-credentials) appends a trailing slash to the
    // endpoint path — `/.sts` is signed as `/.sts/` — so the canonical URI must
    // be whatever arrived, never a normalized form.
    let signing_path = req.signing_path.unwrap_or(req.path);
    let signing_query = req.signing_query.or(req.query).unwrap_or("");

    if !verify_sigv4_signature(
        req.method,
        signing_path,
        signing_query,
        req.headers,
        &sig,
        &creds.secret_access_key,
        &payload_hash,
    )? {
        return Err(ProxyError::SignatureDoesNotMatch);
    }

    Ok(build_caller_identity_response(&creds))
}

fn header<'a>(req: &'a RequestInfo<'_>, name: &str) -> Option<&'a str> {
    req.headers.get(name).and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use http::{HeaderMap, Method};

    fn test_key() -> crate::TokenKey {
        let encoded = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        crate::TokenKey::from_base64(&encoded).unwrap()
    }

    fn req_with_headers<'a>(
        method: &'a Method,
        path: &'a str,
        headers: &'a HeaderMap,
        form_body: Option<&'a str>,
    ) -> RequestInfo<'a> {
        RequestInfo::new(method, path, None, headers, None).with_form_body(form_body)
    }

    #[test]
    fn missing_session_token_is_access_denied() {
        let key = test_key();
        let method = Method::POST;
        let headers = HeaderMap::new();
        let req = req_with_headers(
            &method,
            "/.sts/",
            &headers,
            Some("Action=GetCallerIdentity&Version=2011-06-15"),
        );
        let (status, xml) = handle_get_caller_identity(&req, Some(&key));
        assert_eq!(status, 403, "{xml}");
        assert!(xml.contains("AccessDenied"), "{xml}");
    }

    #[test]
    fn missing_token_key_is_internal_error() {
        let method = Method::POST;
        let headers = HeaderMap::new();
        let req = req_with_headers(&method, "/.sts/", &headers, None);
        let (status, _) = handle_get_caller_identity(&req, None);
        assert_eq!(status, 500);
    }
}
