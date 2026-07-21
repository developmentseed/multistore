//! Parse incoming HTTP requests into typed S3 operations.

use crate::error::ProxyError;
use crate::types::S3Operation;
use http::Method;

/// Extract the bucket and key from a path-style S3 request.
///
/// Path-style: `/{bucket}/{key}`
/// Virtual-hosted-style: Host header `{bucket}.s3.example.com` with path `/{key}`
pub fn parse_s3_request(
    method: &Method,
    uri_path: &str,
    query: Option<&str>,
    headers: &http::HeaderMap,
    host_style: HostStyle,
) -> Result<S3Operation, ProxyError> {
    // GET / with path-style → ListBuckets (no bucket in path)
    if matches!(host_style, HostStyle::Path) && uri_path.trim_start_matches('/').is_empty() {
        if *method == Method::GET {
            return Ok(S3Operation::ListBuckets);
        }
        return Err(ProxyError::InvalidRequest(
            "unsupported operation on /".into(),
        ));
    }

    let (bucket, key) = match host_style {
        HostStyle::Path => parse_path_style(uri_path)?,
        HostStyle::VirtualHosted { bucket } => {
            (bucket, uri_path.trim_start_matches('/').to_string())
        }
    };

    // Server-side copy (CopyObject) arrives as a PUT carrying `x-amz-copy-source`.
    // It cannot go through the presigned forward path (which would drop the
    // header and overwrite the destination with an empty body), so it parses
    // into its own operation handled by `execute_copy`. Callers that invoke
    // `build_s3_operation` directly (custom resolvers) must replicate this
    // check — `build_s3_operation` has no access to headers.
    if *method == Method::PUT {
        if let Some(copy_source) = headers.get("x-amz-copy-source") {
            let copy_source = copy_source.to_str().map_err(|_| {
                ProxyError::InvalidRequest("x-amz-copy-source is not valid UTF-8".into())
            })?;
            return build_copy_object(bucket, key, copy_source, query);
        }
    }

    build_s3_operation(method, bucket, key, query)
}

/// Build a [`CopyObject`](S3Operation::CopyObject) from the destination
/// bucket/key and the `x-amz-copy-source` header value.
///
/// `UploadPartCopy` (a copy-source PUT carrying `uploadId`/`partNumber`) is not
/// supported and is rejected as `NotImplemented` — server-side multipart copy
/// is a separate feature from single-request `CopyObject`.
fn build_copy_object(
    dest_bucket: String,
    dest_key: String,
    copy_source: &str,
    query: Option<&str>,
) -> Result<S3Operation, ProxyError> {
    let query_params = parse_query_params(query);
    if query_params.iter().any(|(k, _)| k == "uploadId") {
        // ponytail: UploadPartCopy deferred — same copy-source mechanism, but
        // it targets an in-progress multipart upload. Add when a client needs
        // server-side copy of objects larger than the 5 GB single-copy limit.
        return Err(ProxyError::NotImplemented(
            "server-side multipart copy (UploadPartCopy) is not supported".into(),
        ));
    }

    validate_key(&dest_key)?;
    let (src_bucket, src_key, src_version) = parse_copy_source(copy_source)?;
    validate_key(&src_key)?;

    Ok(S3Operation::CopyObject {
        bucket: dest_bucket,
        key: dest_key,
        src_bucket,
        src_key,
        src_version,
    })
}

/// Parse an `x-amz-copy-source` value into `(bucket, key, versionId)`.
///
/// The wire format is `[/]sourcebucket/sourcekey[?versionId=id]` with the key
/// percent-encoded (per the S3 spec). The key is decoded to its client-visible
/// form here; the backend copy-source header re-encodes it against the backend
/// key space when the copy is dispatched.
fn parse_copy_source(raw: &str) -> Result<(String, String, Option<String>), ProxyError> {
    let s = raw.strip_prefix('/').unwrap_or(raw);
    let (path, version) = match s.split_once("?versionId=") {
        Some((p, v)) => (p, (!v.is_empty()).then(|| v.to_string())),
        None => (s, None),
    };
    let (bucket, key_encoded) = path.split_once('/').ok_or_else(|| {
        ProxyError::InvalidRequest("x-amz-copy-source must be `bucket/key`".into())
    })?;
    if bucket.is_empty() {
        return Err(ProxyError::InvalidRequest(
            "x-amz-copy-source has an empty bucket".into(),
        ));
    }
    let key = percent_encoding::percent_decode_str(key_encoded)
        .decode_utf8()
        .map_err(|_| ProxyError::InvalidRequest("x-amz-copy-source key is not valid UTF-8".into()))?
        .into_owned();
    if key.is_empty() {
        return Err(ProxyError::InvalidRequest(
            "x-amz-copy-source has an empty key".into(),
        ));
    }
    Ok((bucket.to_string(), key, version))
}

/// Build an [`S3Operation`] from an already-extracted bucket, key, and query.
///
/// This is used by both [`parse_s3_request`] and custom resolvers that parse
/// the path themselves (e.g., Source Cooperative).
pub fn build_s3_operation(
    method: &Method,
    bucket: String,
    key: String,
    query: Option<&str>,
) -> Result<S3Operation, ProxyError> {
    validate_key(&key)?;
    let query_params = parse_query_params(query);

    // Check for multipart upload query params
    let upload_id = query_params
        .iter()
        .find(|(k, _)| k == "uploadId")
        .map(|(_, v)| v.clone());

    let has_uploads = query_params.iter().any(|(k, _)| k == "uploads");
    let has_delete = query_params.iter().any(|(k, _)| k == "delete");

    match *method {
        Method::GET => {
            if key.is_empty() {
                // ListBucket — pass the raw query string through so the proxy
                // can forward all list params (prefix, delimiter, max-keys,
                // continuation-token, list-type, start-after, etc.) to the backend.
                Ok(S3Operation::ListBucket {
                    bucket,
                    raw_query: query.map(|q| q.to_string()),
                })
            } else {
                Ok(S3Operation::GetObject { bucket, key })
            }
        }
        Method::HEAD => Ok(S3Operation::HeadObject { bucket, key }),
        Method::PUT => {
            if let Some(upload_id) = upload_id {
                let part_number = query_params
                    .iter()
                    .find(|(k, _)| k == "partNumber")
                    .and_then(|(_, v)| v.parse().ok())
                    .ok_or_else(|| ProxyError::InvalidRequest("missing partNumber".into()))?;

                Ok(S3Operation::UploadPart {
                    bucket,
                    key,
                    upload_id,
                    part_number,
                })
            } else {
                // `x-amz-copy-source` (CopyObject) is handled upstream in
                // `parse_s3_request` before it reaches here. Callers that invoke
                // `build_s3_operation` directly (custom resolvers) are
                // responsible for their own copy-source handling.
                // ponytail: deferred — trailer checksums (`x-amz-checksum-*`)
                // sent on writes are dropped, not forwarded; they need the
                // header-signing forward path. See
                // .plans/2026-06-23-data-edit-operations-design.md.
                Ok(S3Operation::PutObject { bucket, key })
            }
        }
        Method::POST => {
            if has_uploads {
                Ok(S3Operation::CreateMultipartUpload { bucket, key })
            } else if let Some(upload_id) = upload_id {
                Ok(S3Operation::CompleteMultipartUpload {
                    bucket,
                    key,
                    upload_id,
                })
            } else if has_delete {
                // Batch delete: `POST /{bucket}?delete` with an XML body listing
                // keys. The keys (and per-key authorization) are handled once the
                // body is materialized.
                Ok(S3Operation::DeleteObjects { bucket })
            } else {
                Err(ProxyError::InvalidRequest(
                    "unsupported POST operation".into(),
                ))
            }
        }
        Method::DELETE => {
            if let Some(upload_id) = upload_id {
                Ok(S3Operation::AbortMultipartUpload {
                    bucket,
                    key,
                    upload_id,
                })
            } else if !key.is_empty() {
                // ponytail: deferred — versioned delete (`?versionId=`) and MFA
                // delete are not handled; the version is ignored and the current
                // object is deleted. Upgrade path: thread version-id through the
                // forward. See .plans/2026-06-23-data-edit-operations-design.md.
                Ok(S3Operation::DeleteObject { bucket, key })
            } else {
                Err(ProxyError::InvalidRequest(
                    "unsupported DELETE operation".into(),
                ))
            }
        }
        _ => Err(ProxyError::InvalidRequest(format!(
            "unsupported method: {}",
            method
        ))),
    }
}

/// Validate a client-visible object key before any backend path is built.
///
/// Every backend URL builder must agree on what a key addresses. The
/// presigned path's `Path::parse` rejects empty and `.`/`..` segments but
/// silently strips a leading/trailing `/`; the raw-signed path
/// (`build_backend_url`) would accept all of them — writing objects the
/// presigned path can't address, breaking listings (object_store fails to
/// parse listed keys with empty segments), and letting a literal `..` reach
/// URL normalization. Reject the whole class loudly, once, for every keyed
/// operation. Real S3 accepts these keys; the proxy is deliberately
/// stricter. Batch-delete body keys are deliberately exempt — they never
/// enter a URL path, and permissiveness there is the remediation route for
/// legacy degenerate keys already on a backend.
pub fn validate_key(key: &str) -> Result<(), ProxyError> {
    if key.is_empty() {
        return Ok(()); // bucket-level operation
    }
    let degenerate_segment = key
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == "..");
    if degenerate_segment || key.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ProxyError::InvalidRequest(format!(
            "invalid object key {key:?}: empty, `.`, or `..` path segments, \
             leading/trailing slashes, and control characters are not allowed"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub enum HostStyle {
    /// Path-style: `/{bucket}/{key}`
    Path,
    /// Virtual-hosted-style: bucket extracted from Host header.
    VirtualHosted { bucket: String },
}

fn parse_path_style(path: &str) -> Result<(String, String), ProxyError> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidRequest("empty path".into()));
    }

    match trimmed.split_once('/') {
        Some((bucket, key)) => Ok((bucket.to_string(), key.to_string())),
        None => Ok((trimmed.to_string(), String::new())),
    }
}

fn parse_query_params(query: Option<&str>) -> Vec<(String, String)> {
    query
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(
        method: Method,
        path: &str,
        query: Option<&str>,
        headers: &http::HeaderMap,
    ) -> Result<S3Operation, ProxyError> {
        parse_s3_request(&method, path, query, headers, HostStyle::Path)
    }

    #[test]
    fn batch_delete_parses_as_delete_objects() {
        let op = parse(
            Method::POST,
            "/my-bucket",
            Some("delete"),
            &http::HeaderMap::new(),
        )
        .unwrap();
        assert!(
            matches!(op, S3Operation::DeleteObjects { ref bucket } if bucket == "my-bucket"),
            "POST ?delete should parse as DeleteObjects, got {op:?}"
        );
    }

    #[test]
    fn post_without_known_subresource_is_rejected() {
        let err = parse(
            Method::POST,
            "/my-bucket/key",
            None,
            &http::HeaderMap::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ProxyError::InvalidRequest(_)));
    }

    #[test]
    fn copy_source_put_parses_as_copy_object() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-copy-source", "/src-bucket/src-key".parse().unwrap());
        let op = parse(Method::PUT, "/dst-bucket/dst-key", None, &headers).unwrap();
        assert!(
            matches!(
                op,
                S3Operation::CopyObject {
                    ref bucket,
                    ref key,
                    ref src_bucket,
                    ref src_key,
                    src_version: None,
                } if bucket == "dst-bucket"
                    && key == "dst-key"
                    && src_bucket == "src-bucket"
                    && src_key == "src-key"
            ),
            "copy-source PUT must parse as CopyObject, got {op:?}"
        );
    }

    #[test]
    fn copy_source_without_leading_slash_and_with_version_parses() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            "src-bucket/a%20b.txt?versionId=v1".parse().unwrap(),
        );
        let op = parse(Method::PUT, "/dst/k", None, &headers).unwrap();
        match op {
            S3Operation::CopyObject {
                src_bucket,
                src_key,
                src_version,
                ..
            } => {
                assert_eq!(src_bucket, "src-bucket");
                // The encoded key is decoded to its client-visible form.
                assert_eq!(src_key, "a b.txt");
                assert_eq!(src_version.as_deref(), Some("v1"));
            }
            other => panic!("expected CopyObject, got {other:?}"),
        }
    }

    #[test]
    fn copy_source_with_empty_version_id_parses_key_without_suffix() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            "src-bucket/key?versionId=".parse().unwrap(),
        );
        let op = parse(Method::PUT, "/dst/k", None, &headers).unwrap();
        match op {
            S3Operation::CopyObject {
                src_key,
                src_version,
                ..
            } => {
                // The `?versionId=` suffix must be stripped, not glued onto the key.
                assert_eq!(src_key, "key");
                assert_eq!(src_version, None);
            }
            other => panic!("expected CopyObject, got {other:?}"),
        }
    }

    #[test]
    fn upload_part_copy_is_rejected_not_implemented() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-copy-source", "/src/k".parse().unwrap());
        let err = parse(
            Method::PUT,
            "/dst/k",
            Some("partNumber=1&uploadId=abc"),
            &headers,
        )
        .unwrap_err();
        assert!(
            matches!(err, ProxyError::NotImplemented(_)),
            "UploadPartCopy must be NotImplemented, got {err:?}"
        );
    }

    #[test]
    fn copy_source_with_malformed_value_is_rejected() {
        let headers = |v: &str| {
            let mut h = http::HeaderMap::new();
            h.insert("x-amz-copy-source", v.parse().unwrap());
            h
        };
        for bad in ["", "/", "no-slash", "src-bucket/", "/src-bucket/"] {
            let err = parse(Method::PUT, "/dst/k", None, &headers(bad)).unwrap_err();
            assert!(
                matches!(err, ProxyError::InvalidRequest(_)),
                "copy-source {bad:?} must be InvalidRequest, got {err:?}"
            );
        }
    }

    #[test]
    fn plain_put_still_parses_as_put_object() {
        let op = parse(Method::PUT, "/b/k.txt", None, &http::HeaderMap::new()).unwrap();
        assert!(matches!(op, S3Operation::PutObject { .. }));
    }

    #[test]
    fn degenerate_keys_are_rejected_for_every_keyed_operation() {
        let headers = http::HeaderMap::new();
        for key in [
            "a//b.txt",
            "a/./b.txt",
            "a/../b.txt",
            "/a.txt",
            "dir/",
            "a\nb",
        ] {
            for (method, query) in [
                (Method::GET, None),
                (Method::PUT, None),
                (Method::DELETE, None),
                (Method::POST, Some("uploads")),
            ] {
                let err = build_s3_operation(&method, "b".into(), key.into(), query).unwrap_err();
                assert!(
                    matches!(err, ProxyError::InvalidRequest(_)),
                    "{method} of key {key:?} must be InvalidRequest, got {err:?}"
                );
            }
        }
        // Bucket-level operations (empty key) are unaffected.
        assert!(parse(Method::GET, "/b", None, &headers).is_ok());
        assert!(parse(Method::POST, "/b", Some("delete"), &headers).is_ok());
    }
}
