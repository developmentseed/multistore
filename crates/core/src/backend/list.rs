//! Direct S3 ListObjectsV2 via raw HTTP.
//!
//! Bypasses `object_store`'s `Path::parse()` which rejects keys containing `//`.
//! Uses the same `send_raw` + `sign_s3_request` infrastructure as multipart uploads.

use crate::api::raw_list::{RawPaginatedListResult, S3ListResponse};
use crate::backend::multipart::sign_s3_request;
use crate::backend::request_signer::UNSIGNED_PAYLOAD;
use crate::backend::ProxyBackend;
use crate::error::ProxyError;
use crate::types::BucketConfig;
use http::HeaderMap;

/// Execute an S3 ListObjectsV2 request directly via raw HTTP.
///
/// This avoids `object_store::Path` normalization, preserving keys with `//`
/// or other characters that `Path::parse()` would reject.
pub async fn s3_list<B: ProxyBackend>(
    backend: &B,
    config: &BucketConfig,
    prefix: Option<&str>,
    delimiter: Option<&str>,
    max_keys: usize,
    continuation_token: Option<&str>,
    start_after: Option<&str>,
) -> Result<RawPaginatedListResult, ProxyError> {
    let url = build_list_url(config, prefix, delimiter, max_keys, continuation_token, start_after)?;

    let mut headers = HeaderMap::new();
    sign_s3_request(
        &http::Method::GET,
        &url,
        &mut headers,
        config,
        UNSIGNED_PAYLOAD,
    )?;

    tracing::debug!(url = %url, "s3_list via raw HTTP");

    let raw_resp = backend
        .send_raw(http::Method::GET, url, headers, bytes::Bytes::new())
        .await?;

    if raw_resp.status < 200 || raw_resp.status >= 300 {
        let body_str = String::from_utf8_lossy(&raw_resp.body);
        return Err(ProxyError::BackendError(format!(
            "S3 ListObjectsV2 returned status {}: {}",
            raw_resp.status, body_str
        )));
    }

    let s3_resp: S3ListResponse = quick_xml::de::from_reader(raw_resp.body.as_ref())
        .map_err(|e| ProxyError::Internal(format!("failed to parse ListObjectsV2 XML: {}", e)))?;

    Ok(s3_resp.into())
}

/// Build the ListObjectsV2 URL from bucket config and query parameters.
fn build_list_url(
    config: &BucketConfig,
    prefix: Option<&str>,
    delimiter: Option<&str>,
    max_keys: usize,
    continuation_token: Option<&str>,
    start_after: Option<&str>,
) -> Result<String, ProxyError> {
    let endpoint = config.option("endpoint").unwrap_or("");
    let base = endpoint.trim_end_matches('/');
    let bucket = config.option("bucket_name").unwrap_or("");

    let path = if bucket.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base, bucket)
    };

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("list-type", "2");
    serializer.append_pair("max-keys", &max_keys.to_string());

    if let Some(p) = prefix {
        if !p.is_empty() {
            serializer.append_pair("prefix", p);
        }
    }
    if let Some(d) = delimiter {
        if !d.is_empty() {
            serializer.append_pair("delimiter", d);
        }
    }
    if let Some(token) = continuation_token {
        serializer.append_pair("continuation-token", token);
    }
    if let Some(sa) = start_after {
        serializer.append_pair("start-after", sa);
    }

    let query = serializer.finish();
    Ok(format!("{}?{}", path, query))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config(endpoint: &str, bucket: &str) -> BucketConfig {
        let mut opts = HashMap::new();
        opts.insert("endpoint".into(), endpoint.into());
        opts.insert("bucket_name".into(), bucket.into());
        BucketConfig {
            name: "test".into(),
            backend_type: "s3".into(),
            backend_prefix: None,
            anonymous_access: true,
            allowed_roles: vec![],
            backend_options: opts,
        }
    }

    #[test]
    fn build_list_url_basic() {
        let config = test_config("https://s3.amazonaws.com", "my-bucket");
        let url = build_list_url(&config, Some("media/"), Some("/"), 1000, None, None).unwrap();
        assert!(url.starts_with("https://s3.amazonaws.com/my-bucket?"));
        assert!(url.contains("list-type=2"));
        assert!(url.contains("max-keys=1000"));
        assert!(url.contains("prefix=media%2F"));
        assert!(url.contains("delimiter=%2F"));
    }

    #[test]
    fn build_list_url_with_continuation() {
        let config = test_config("https://s3.amazonaws.com", "bucket");
        let url = build_list_url(&config, None, None, 100, Some("token123"), None).unwrap();
        assert!(url.contains("continuation-token=token123"));
        assert!(!url.contains("prefix="));
        assert!(!url.contains("delimiter="));
    }

    #[test]
    fn build_list_url_empty_bucket() {
        let config = test_config("https://storage.example.com/path", "");
        let url = build_list_url(&config, Some("dir/"), Some("/"), 500, None, None).unwrap();
        assert!(url.starts_with("https://storage.example.com/path?"));
    }

    #[test]
    fn build_list_url_with_start_after() {
        let config = test_config("https://s3.amazonaws.com", "bucket");
        let url =
            build_list_url(&config, Some("p/"), Some("/"), 10, None, Some("p/file.txt")).unwrap();
        assert!(url.contains("start-after=p%2Ffile.txt"));
    }
}
