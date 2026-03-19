//! Outbound SigV4 request signing.
//!
//! [`S3RequestSigner`] signs raw HTTP requests destined for S3-compatible
//! backends using AWS Signature Version 4. Used for multipart operations
//! (CreateMultipartUpload, UploadPart, CompleteMultipartUpload,
//! AbortMultipartUpload) that go through [`backend::ProxyBackend::send_raw`](crate::backend::ProxyBackend::send_raw).

use crate::auth::sigv4::hmac_sha256;
use crate::error::ProxyError;
use http::HeaderMap;

/// Signs outbound HTTP requests using AWS SigV4.
pub struct S3RequestSigner {
    /// AWS access key ID.
    pub access_key_id: String,
    /// AWS secret access key used for HMAC signing.
    pub secret_access_key: String,
    /// AWS region (e.g. "us-east-1").
    pub region: String,
    /// AWS service name (typically "s3").
    pub service: String,
    /// Optional session token for temporary credentials.
    pub session_token: Option<String>,
}

impl S3RequestSigner {
    /// Create a new signer for the given credentials and region.
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        region: String,
        session_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            region,
            service: "s3".to_string(),
            session_token,
        }
    }

    /// Sign an outbound request using AWS SigV4.
    ///
    /// This adds Authorization, x-amz-date, x-amz-content-sha256, and Host
    /// headers to the provided header map.
    pub fn sign_request(
        &self,
        method: &http::Method,
        url: &url::Url,
        headers: &mut HeaderMap,
        payload_hash: &str,
    ) -> Result<(), ProxyError> {
        use chrono::Utc;

        let now = Utc::now();
        let date_stamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Set required headers
        headers.insert("x-amz-date", amz_date.parse().unwrap());
        headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());

        if let Some(token) = &self.session_token {
            headers.insert("x-amz-security-token", token.parse().unwrap());
        }

        let host = url
            .host_str()
            .ok_or_else(|| ProxyError::Internal("no host in URL".into()))?;
        let host_header = if let Some(port) = url.port() {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };
        headers.insert("host", host_header.parse().unwrap());

        // Canonical request
        let canonical_uri = url.path();
        let canonical_querystring = url.query().unwrap_or("");

        let mut signed_header_names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
        signed_header_names.sort();

        let canonical_headers: String = signed_header_names
            .iter()
            .map(|k| {
                let v = headers.get(*k).unwrap().to_str().unwrap_or("").trim();
                format!("{}:{}\n", k, v)
            })
            .collect();

        let signed_headers = signed_header_names.join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash
        );

        // String to sign
        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            date_stamp, self.region, self.service
        );

        use sha2::{Digest, Sha256};
        let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date, credential_scope, canonical_request_hash
        );

        // Derive signing key
        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        )?;
        let k_region = hmac_sha256(&k_date, self.region.as_bytes())?;
        let k_service = hmac_sha256(&k_region, self.service.as_bytes())?;
        let signing_key = hmac_sha256(&k_service, b"aws4_request")?;

        // Signature
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

        // Authorization header
        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, credential_scope, signed_headers, signature
        );
        headers.insert("authorization", auth_header.parse().unwrap());

        Ok(())
    }
}

/// Hash a payload for SigV4. For streaming/unsigned payloads, use the
/// special sentinel value.
pub fn hash_payload(payload: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(payload))
}

/// The SigV4 sentinel for unsigned payloads (used with streaming uploads).
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The SigV4 sentinel for streaming payloads.
pub const STREAMING_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
