//! Multipart URL building and request signing for S3-compatible backends.
//!
//! These helpers are used by [`Gateway::execute_multipart`](crate::proxy::Gateway)
//! for CreateMultipartUpload, UploadPart, CompleteMultipartUpload, and
//! AbortMultipartUpload operations.

use crate::backend::request_signer::S3RequestSigner;
use crate::error::ProxyError;
use crate::types::{BucketConfig, S3Operation};
use http::{HeaderMap, Method};
use url::Url;

/// Build the backend URL for an S3 operation.
///
/// Used for multipart operations that go through raw signed HTTP.
pub fn build_backend_url(
    config: &BucketConfig,
    operation: &S3Operation,
) -> Result<String, ProxyError> {
    let endpoint = config.option("endpoint").unwrap_or("");
    let base = endpoint.trim_end_matches('/');
    let bucket = config.option("bucket_name").unwrap_or("");
    let bucket_is_empty = bucket.is_empty();

    let mut key = String::new();
    if let Some(prefix) = &config.backend_prefix {
        key.push_str(prefix.trim_end_matches('/'));
        key.push('/');
    }
    key.push_str(operation.key());

    let mut url = if bucket_is_empty {
        format!("{}/{}", base, key)
    } else {
        format!("{}/{}/{}", base, bucket, key)
    };

    match operation {
        S3Operation::CreateMultipartUpload { .. } => {
            url.push_str("?uploads");
        }
        S3Operation::UploadPart {
            upload_id,
            part_number,
            ..
        } => {
            let qs = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("partNumber", &part_number.to_string())
                .append_pair("uploadId", upload_id)
                .finish();
            url.push('?');
            url.push_str(&qs);
        }
        S3Operation::CompleteMultipartUpload { upload_id, .. }
        | S3Operation::AbortMultipartUpload { upload_id, .. } => {
            let qs = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("uploadId", upload_id)
                .finish();
            url.push('?');
            url.push_str(&qs);
        }
        _ => {}
    }

    Ok(url)
}

/// Sign an outbound S3 request using credentials from the bucket config.
///
/// Used for multipart operations only. CRUD operations use presigned URLs.
pub(crate) fn sign_s3_request(
    method: &Method,
    url: &str,
    headers: &mut HeaderMap,
    config: &BucketConfig,
    payload_hash: &str,
) -> Result<(), ProxyError> {
    let access_key = config.option("access_key_id").unwrap_or("");
    let secret_key = config.option("secret_access_key").unwrap_or("");
    let region = config.option("region").unwrap_or("us-east-1");
    let has_credentials = !access_key.is_empty() && !secret_key.is_empty();

    let parsed_url =
        Url::parse(url).map_err(|e| ProxyError::Internal(format!("invalid backend URL: {}", e)))?;

    if has_credentials {
        let session_token = config.option("token").map(|s| s.to_string());
        let signer = S3RequestSigner::new(
            access_key.to_string(),
            secret_key.to_string(),
            region.to_string(),
            session_token,
        );
        signer.sign_request(method, &parsed_url, headers, payload_hash)?;
    } else {
        let host = parsed_url
            .host_str()
            .ok_or_else(|| ProxyError::Internal("no host in URL".into()))?;
        let host_header = if let Some(port) = parsed_url.port() {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };
        headers.insert("host", host_header.parse().unwrap());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_bucket_config() -> BucketConfig {
        let mut backend_options = HashMap::new();
        backend_options.insert(
            "endpoint".into(),
            "https://s3.us-east-1.amazonaws.com".into(),
        );
        backend_options.insert("bucket_name".into(), "my-backend-bucket".into());
        BucketConfig {
            name: "test".into(),
            backend_type: "s3".into(),
            backend_prefix: None,
            anonymous_access: false,
            allowed_roles: vec![],
            backend_options,
            cors: None,
        }
    }

    #[test]
    fn upload_id_with_special_chars_is_encoded() {
        let config = test_bucket_config();
        let malicious_upload_id = "abc&x-amz-acl=public-read&foo=bar";
        let op = S3Operation::UploadPart {
            bucket: "test".into(),
            key: "file.bin".into(),
            upload_id: malicious_upload_id.into(),
            part_number: 1,
        };

        let url = build_backend_url(&config, &op).unwrap();

        // The & and = characters in upload_id must be percent-encoded so they
        // cannot act as query parameter separators/assignments.
        let query = url.split_once('?').unwrap().1;
        let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // Should be exactly 2 params: partNumber and uploadId
        assert_eq!(
            params.len(),
            2,
            "expected 2 query params, got: {:?}",
            params
        );
        assert!(params.iter().any(|(k, v)| k == "partNumber" && v == "1"));
        assert!(params
            .iter()
            .any(|(k, v)| k == "uploadId" && v == malicious_upload_id));
    }

    #[test]
    fn upload_id_encoded_in_complete_multipart() {
        let config = test_bucket_config();
        let op = S3Operation::CompleteMultipartUpload {
            bucket: "test".into(),
            key: "file.bin".into(),
            upload_id: "id&injected=true".into(),
        };

        let url = build_backend_url(&config, &op).unwrap();

        assert!(
            !url.contains("injected=true"),
            "upload_id was not encoded: {}",
            url
        );
    }

    #[test]
    fn normal_upload_id_works() {
        let config = test_bucket_config();
        let op = S3Operation::UploadPart {
            bucket: "test".into(),
            key: "file.bin".into(),
            upload_id: "2~abcdef1234567890".into(),
            part_number: 3,
        };

        let url = build_backend_url(&config, &op).unwrap();

        assert!(url.starts_with("https://s3.us-east-1.amazonaws.com/my-backend-bucket/file.bin?"));
        assert!(url.contains("partNumber=3"));
        assert!(
            url.contains("uploadId=2~abcdef1234567890")
                || url.contains("uploadId=2%7Eabcdef1234567890")
        );
    }
}
