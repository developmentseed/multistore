//! SigV4 signature parsing and verification for inbound requests.
//!
//! Two request shapes are supported:
//! - **Header auth** — SigV4 material in the `Authorization` header
//!   ([`parse_sigv4_auth`] + [`verify_sigv4_signature`]).
//! - **Presigned URLs** — SigV4 material in the query string
//!   ([`parse_sigv4_presigned`] + [`verify_sigv4_presigned`]). Browsers can't
//!   set an `Authorization` header, so `<img>`/`<a>`/`fetch` use this form.

use crate::error::ProxyError;
use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Parsed SigV4 credential scope, signed headers, and signature.
///
/// Shared by both header-based and presigned requests — only the *source* of
/// these fields differs, not their meaning.
#[derive(Debug, Clone)]
pub struct SigV4Auth {
    /// The access key ID from the credential scope.
    pub access_key_id: String,
    /// The date stamp (YYYYMMDD) from the credential scope.
    pub date_stamp: String,
    /// The AWS region from the credential scope.
    pub region: String,
    /// The AWS service name from the credential scope (e.g. "s3").
    pub service: String,
    /// The list of header names included in the signature.
    pub signed_headers: Vec<String>,
    /// The hex-encoded HMAC-SHA256 signature.
    pub signature: String,
}

/// SigV4 material extracted from a presigned URL's query string.
#[derive(Debug, Clone)]
pub struct PresignedSig {
    /// The credential scope, signed headers, and signature.
    pub auth: SigV4Auth,
    /// The `X-Amz-Date` query param (`YYYYMMDDTHHMMSSZ`) — used as the
    /// string-to-sign date instead of the `x-amz-date` header.
    pub amz_date: String,
    /// The `X-Amz-Expires` value, in seconds after `amz_date`.
    pub expires: u64,
    /// The `X-Amz-Security-Token`, percent-decoded, if present.
    pub session_token: Option<String>,
}

/// Parse a SigV4 Authorization header.
///
/// Format: `AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request,
///           SignedHeaders=host;x-amz-date, Signature=abcdef...`
pub fn parse_sigv4_auth(auth_header: &str) -> Result<SigV4Auth, ProxyError> {
    let auth_header = auth_header
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or_else(|| ProxyError::InvalidRequest("invalid auth scheme".into()))?;

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;

    for part in auth_header.split(", ") {
        if let Some(val) = part.strip_prefix("Credential=") {
            credential = Some(val);
        } else if let Some(val) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(val);
        } else if let Some(val) = part.strip_prefix("Signature=") {
            signature = Some(val);
        }
    }

    let credential =
        credential.ok_or_else(|| ProxyError::InvalidRequest("missing Credential".into()))?;
    let signed_headers =
        signed_headers.ok_or_else(|| ProxyError::InvalidRequest("missing SignedHeaders".into()))?;
    let signature =
        signature.ok_or_else(|| ProxyError::InvalidRequest("missing Signature".into()))?;

    build_sigv4_auth(credential, signed_headers, signature)
}

/// Is this query string a SigV4 presigned request?
///
/// True when it carries `X-Amz-Algorithm=AWS4-HMAC-SHA256`.
pub fn is_presigned(query: &str) -> bool {
    query_param(query, "X-Amz-Algorithm").as_deref() == Some("AWS4-HMAC-SHA256")
}

/// Parse SigV4 material from a presigned URL query string.
///
/// Query param *values* are percent-decoded for parsing (e.g. `X-Amz-Credential`
/// arrives as `AKID%2F.../aws4_request`). The raw, still-encoded query string is
/// what gets canonicalized during verification — do not decode it there.
pub fn parse_sigv4_presigned(query: &str) -> Result<PresignedSig, ProxyError> {
    let require = |key: &str| {
        query_param(query, key)
            .map(|v| decode(&v))
            .ok_or_else(|| ProxyError::InvalidRequest(format!("missing {key}")))
    };

    let credential = require("X-Amz-Credential")?;
    let signed_headers = require("X-Amz-SignedHeaders")?;
    let signature = require("X-Amz-Signature")?;
    let amz_date = require("X-Amz-Date")?;
    let expires = require("X-Amz-Expires")?
        .parse::<u64>()
        .map_err(|_| ProxyError::InvalidRequest("invalid X-Amz-Expires".into()))?;

    Ok(PresignedSig {
        auth: build_sigv4_auth(&credential, &signed_headers, &signature)?,
        amz_date,
        expires,
        session_token: query_param(query, "X-Amz-Security-Token").map(|v| decode(&v)),
    })
}

/// Verify a header-auth SigV4 signature against a known secret key.
///
/// The string-to-sign date is read from the `x-amz-date` header; the payload
/// hash is supplied by the caller (from `x-amz-content-sha256`).
pub fn verify_sigv4_signature(
    method: &http::Method,
    uri_path: &str,
    query_string: &str,
    headers: &HeaderMap,
    auth: &SigV4Auth,
    secret_access_key: &str,
    payload_hash: &str,
) -> Result<bool, ProxyError> {
    let canonical_query = canonicalize_query_string(query_string);
    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    verify_signed(
        method,
        uri_path,
        &canonical_query,
        headers,
        auth,
        secret_access_key,
        payload_hash,
        amz_date,
    )
}

/// Verify a presigned-URL SigV4 signature against a known secret key.
///
/// Differs from header auth: `X-Amz-Signature` is excluded from the canonical
/// query, the payload hash is the literal `UNSIGNED-PAYLOAD`, and the
/// string-to-sign date comes from the `X-Amz-Date` query param.
pub fn verify_sigv4_presigned(
    method: &http::Method,
    uri_path: &str,
    query_string: &str,
    headers: &HeaderMap,
    auth: &SigV4Auth,
    secret_access_key: &str,
    amz_date: &str,
) -> Result<bool, ProxyError> {
    // Canonical query is every param except the signature itself, sorted.
    let stripped: String = query_string
        .split('&')
        .filter(|p| !p.starts_with("X-Amz-Signature="))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_query = canonicalize_query_string(&stripped);
    verify_signed(
        method,
        uri_path,
        &canonical_query,
        headers,
        auth,
        secret_access_key,
        "UNSIGNED-PAYLOAD",
        amz_date,
    )
}

/// Shared core: reconstruct the canonical request, derive the signing key, and
/// constant-time compare against the provided signature. Callers supply the
/// already-canonicalized query, payload hash, and string-to-sign date so the
/// header vs. presigned differences live entirely in the thin wrappers above.
#[allow(clippy::too_many_arguments)]
fn verify_signed(
    method: &http::Method,
    uri_path: &str,
    canonical_query: &str,
    headers: &HeaderMap,
    auth: &SigV4Auth,
    secret_access_key: &str,
    payload_hash: &str,
    amz_date: &str,
) -> Result<bool, ProxyError> {
    let canonical_headers: String = auth
        .signed_headers
        .iter()
        .map(|name| {
            let value = headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .trim();
            format!("{}:{}\n", name, value)
        })
        .collect();

    let signed_headers_str = auth.signed_headers.join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri_path, canonical_query, canonical_headers, signed_headers_str, payload_hash
    );

    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        auth.date_stamp, auth.region, auth.service
    );

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );

    // Derive signing key
    let k_date = hmac_sha256(
        format!("AWS4{}", secret_access_key).as_bytes(),
        auth.date_stamp.as_bytes(),
    )?;
    let k_region = hmac_sha256(&k_date, auth.region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, auth.service.as_bytes())?;
    let signing_key = hmac_sha256(&k_service, b"aws4_request")?;

    let expected_signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    let matched = constant_time_eq(expected_signature.as_bytes(), auth.signature.as_bytes());

    if !matched {
        tracing::warn!(
            access_key_id = %auth.access_key_id,
            region = %auth.region,
            "SigV4 signature mismatch"
        );
        tracing::debug!(
            canonical_request = %canonical_request,
            string_to_sign = %string_to_sign,
            "SigV4 signature mismatch details — compare canonical_request with client-side (aws --debug)"
        );
    }

    Ok(matched)
}

/// Build a [`SigV4Auth`] from the raw credential scope, signed headers, and
/// signature strings (decoded — no percent-encoding).
fn build_sigv4_auth(
    credential: &str,
    signed_headers: &str,
    signature: &str,
) -> Result<SigV4Auth, ProxyError> {
    // Parse credential: AKID/date/region/service/aws4_request
    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() != 5 || cred_parts[4] != "aws4_request" {
        return Err(ProxyError::InvalidRequest(
            "malformed credential scope".into(),
        ));
    }

    Ok(SigV4Auth {
        access_key_id: cred_parts[0].to_string(),
        date_stamp: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        service: cred_parts[3].to_string(),
        signed_headers: signed_headers.split(';').map(String::from).collect(),
        signature: signature.to_string(),
    })
}

/// Look up a query param by exact key, returning its raw (still-encoded) value.
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

/// Percent-decode a query param value (lossy on invalid UTF-8).
fn decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

/// Sort query string parameters for SigV4 canonical request construction.
pub(crate) fn canonicalize_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut parts: Vec<&str> = query.split('&').collect();
    parts.sort_unstable();
    parts.join("&")
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| ProxyError::Internal(e.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
