//! SigV4 signature parsing and verification for inbound requests.

use crate::error::ProxyError;
use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Parsed SigV4 Authorization header.
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

/// Verify a SigV4 signature against a known secret key.
pub fn verify_sigv4_signature(
    method: &http::Method,
    uri_path: &str,
    query_string: &str,
    headers: &HeaderMap,
    auth: &SigV4Auth,
    secret_access_key: &str,
    payload_hash: &str,
) -> Result<bool, ProxyError> {
    // Reconstruct canonical request
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

    // SigV4 requires query parameters sorted alphabetically by key (then value).
    // The raw query string from the URL may not be sorted, but the client SDK
    // sorts them when constructing the canonical request for signing.
    let canonical_query = canonicalize_query_string(query_string);

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, uri_path, canonical_query, canonical_headers, signed_headers_str, payload_hash
    );

    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        auth.date_stamp, auth.region, auth.service
    );

    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

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

/// Build the SigV4 canonical query string: every parameter as `key=value`,
/// sorted.
///
/// A value-less flag parameter (e.g. `?uploads`, `?delete`) is canonicalized
/// with an empty value and a trailing `=` per the SigV4 spec. Clients (and
/// backends) sign it that way, so the proxy must reconstruct it identically on
/// both the inbound-verification and outbound-signing sides or the signature
/// will not match. Empty segments (from a stray `&`) are dropped.
pub(crate) fn canonicalize_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    // Borrow params that are already `key=value`; only the value-less flags
    // (`?delete`, `?uploads`) need an owned `key=`. This keeps the common path
    // allocation-free on the per-request signing/verification hot path.
    let mut parts: Vec<std::borrow::Cow<str>> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            if p.contains('=') {
                std::borrow::Cow::Borrowed(p)
            } else {
                std::borrow::Cow::Owned(format!("{p}="))
            }
        })
        .collect();
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

#[cfg(test)]
mod tests {
    use super::canonicalize_query_string;

    #[test]
    fn empty_query_is_empty() {
        assert_eq!(canonicalize_query_string(""), "");
    }

    #[test]
    fn value_less_flag_gets_trailing_equals() {
        // The bug that broke multipart and batch delete: `?uploads` / `?delete`
        // must canonicalize to `uploads=` / `delete=`.
        assert_eq!(canonicalize_query_string("uploads"), "uploads=");
        assert_eq!(canonicalize_query_string("delete"), "delete=");
    }

    #[test]
    fn valued_params_are_sorted_and_unchanged() {
        assert_eq!(
            canonicalize_query_string("list-type=2&prefix=foo"),
            "list-type=2&prefix=foo"
        );
        // Sorting is by the full encoded parameter.
        assert_eq!(
            canonicalize_query_string("partNumber=1&uploadId=abc"),
            "partNumber=1&uploadId=abc"
        );
        assert_eq!(canonicalize_query_string("b=2&a=1"), "a=1&b=2");
    }

    #[test]
    fn mixed_flag_and_valued_params() {
        // Real shape of a versioned delete-style request.
        assert_eq!(
            canonicalize_query_string("versionId=v1&delete"),
            "delete=&versionId=v1"
        );
    }

    #[test]
    fn stray_empty_segments_are_dropped() {
        assert_eq!(canonicalize_query_string("delete&"), "delete=");
    }
}
