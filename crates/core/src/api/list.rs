//! LIST-specific helpers for building S3 ListObjectsV2 XML responses.
//!
//! Extracted from `proxy.rs` to keep the gateway focused on orchestration.

use std::collections::HashSet;

use serde::Deserialize;

use crate::api::list_rewrite::ListRewrite;
use crate::api::response::{ListBucketResult, ListBucketResultV1, ListCommonPrefix, ListContents};
use crate::error::ProxyError;
use crate::types::BucketConfig;

/// Parameters for building the S3 ListObjectsV2 XML response.
pub(crate) struct ListXmlParams<'a> {
    pub bucket_name: &'a str,
    pub client_prefix: &'a str,
    pub delimiter: &'a str,
    pub max_keys: usize,
    pub is_truncated: bool,
    pub key_count: usize,
    pub start_after: &'a Option<String>,
    pub continuation_token: &'a Option<String>,
    pub next_continuation_token: Option<String>,
    pub encoding_type: &'a Option<String>,
}

/// All query parameters needed for a LIST operation, parsed in a single pass.
pub struct ListQueryParams {
    /// Key prefix filter (empty string means no filter).
    pub prefix: String,
    /// Delimiter for grouping keys into common prefixes (e.g. "/").
    pub delimiter: String,
    /// Maximum number of keys to return per page (capped at 1000).
    pub max_keys: usize,
    /// Opaque token for fetching the next page of results (V2 only).
    pub continuation_token: Option<String>,
    /// Return keys lexicographically after this value (V2 only).
    pub start_after: Option<String>,
    /// Encoding type for keys/prefixes in the response (e.g. "url").
    pub encoding_type: Option<String>,
    /// V1 pagination marker — return keys after this value.
    pub marker: Option<String>,
    /// Whether this is a V2 list request (`list-type=2`).
    pub is_v2: bool,
}

/// Parse prefix, delimiter, and pagination params from a LIST query string in one pass.
pub fn parse_list_query_params(raw_query: Option<&str>) -> ListQueryParams {
    let mut prefix = None;
    let mut delimiter = None;
    let mut max_keys = None;
    let mut continuation_token = None;
    let mut start_after = None;
    let mut encoding_type = None;
    let mut marker = None;
    let mut is_v2 = false;

    if let Some(q) = raw_query {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            match k.as_ref() {
                "prefix" => prefix = Some(v.into_owned()),
                "delimiter" => delimiter = Some(v.into_owned()),
                "max-keys" => max_keys = Some(v.into_owned()),
                "continuation-token" => continuation_token = Some(v.into_owned()),
                "start-after" => start_after = Some(v.into_owned()),
                "encoding-type" => encoding_type = Some(v.into_owned()),
                "marker" => marker = Some(v.into_owned()),
                "list-type" if v.as_ref() == "2" => {
                    is_v2 = true;
                }
                _ => {}
            }
        }
    }

    ListQueryParams {
        prefix: prefix.unwrap_or_default(),
        delimiter: delimiter.unwrap_or_default(),
        max_keys: max_keys
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000)
            .min(1000),
        continuation_token,
        start_after,
        encoding_type,
        marker,
        is_v2,
    }
}

/// Build the full list prefix including backend_prefix.
pub(crate) fn build_list_prefix(config: &BucketConfig, client_prefix: &str) -> String {
    match &config.backend_prefix {
        Some(prefix) => {
            let bp = prefix.trim_end_matches('/');
            if bp.is_empty() {
                client_prefix.to_string()
            } else {
                let mut full_prefix = String::with_capacity(bp.len() + 1 + client_prefix.len());
                full_prefix.push_str(bp);
                full_prefix.push('/');
                full_prefix.push_str(client_prefix);
                full_prefix
            }
        }
        None => client_prefix.to_string(),
    }
}

/// A ListObjects response parsed leniently from the backend's XML.
///
/// Unlike `object_store::ListResult`, keys are kept as raw byte-preserving
/// `String`s. `object_store::path::Path` **rejects** — and cannot even
/// represent — keys with empty path segments (a `//`), which are perfectly
/// legal opaque S3 keys. Routing list responses through it makes an entire
/// prefix unlistable if a single such key exists (issue #116): S3 serves the
/// key, but the gateway 503s the whole page. We parse the backend XML ourselves
/// and pass keys through untouched so anything listable in S3 stays listable
/// through multistore.
pub(crate) struct BackendListResult {
    /// Object entries, keys exactly as the backend returned them.
    pub objects: Vec<BackendObject>,
    /// Common prefixes (delimiter grouping), with their trailing `/` intact.
    pub common_prefixes: Vec<String>,
    /// Whether more pages are available.
    pub is_truncated: bool,
    /// Opaque token for the next page (V2), echoed straight from the backend.
    pub next_continuation_token: Option<String>,
}

/// A single object entry from a backend list response, key preserved verbatim.
pub(crate) struct BackendObject {
    pub key: String,
    pub last_modified: String,
    pub etag: String,
    pub size: u64,
}

/// Parse a backend `ListBucketResult` (V1 or V2) XML body without normalizing
/// keys, preserving empty path segments that `object_store::Path` would reject.
pub(crate) fn parse_backend_list_xml(xml: &[u8]) -> Result<BackendListResult, ProxyError> {
    #[derive(Deserialize)]
    #[serde(rename = "ListBucketResult")]
    struct Raw {
        #[serde(default, rename = "Contents")]
        contents: Vec<RawContents>,
        #[serde(default, rename = "CommonPrefixes")]
        common_prefixes: Vec<RawPrefix>,
        #[serde(default, rename = "IsTruncated")]
        is_truncated: bool,
        #[serde(default, rename = "NextContinuationToken")]
        next_continuation_token: Option<String>,
    }
    #[derive(Deserialize)]
    struct RawContents {
        #[serde(rename = "Key")]
        key: String,
        #[serde(default, rename = "LastModified")]
        last_modified: String,
        #[serde(default, rename = "ETag")]
        etag: String,
        #[serde(default, rename = "Size")]
        size: u64,
    }
    #[derive(Deserialize)]
    struct RawPrefix {
        #[serde(rename = "Prefix")]
        prefix: String,
    }

    let raw: Raw = quick_xml::de::from_reader(xml).map_err(|e| {
        ProxyError::BackendError(format!("invalid list response from backend: {e}"))
    })?;

    // S3 omits NextContinuationToken when the page isn't truncated; some
    // backends emit an empty element. Normalize empty to None.
    let next_continuation_token = raw.next_continuation_token.filter(|t| !t.is_empty());

    Ok(BackendListResult {
        objects: raw
            .contents
            .into_iter()
            .map(|c| BackendObject {
                key: c.key,
                last_modified: c.last_modified,
                // S3 always returns a quoted ETag; fall back to `""` (matching
                // the empty-ETag placeholder the response builder emits).
                etag: if c.etag.is_empty() {
                    "\"\"".to_string()
                } else {
                    c.etag
                },
                size: c.size,
            })
            .collect(),
        common_prefixes: raw.common_prefixes.into_iter().map(|p| p.prefix).collect(),
        is_truncated: raw.is_truncated,
        next_continuation_token,
    })
}

/// Build the backend URL (endpoint + query) for a ListObjects request.
///
/// The client's `prefix`, `start-after`, and `marker` are mapped into the
/// backend key space (backend prefix prepended). `encoding-type` is
/// deliberately **not** forwarded: we request raw keys from the backend and
/// apply the client's requested encoding ourselves, avoiding a double-encode.
/// Query values are percent-encoded with the SigV4-canonical set (space →
/// `%20`) so [`sign_s3_request`](crate::backend::multipart::sign_s3_request)
/// signs exactly what we send.
pub(crate) fn build_backend_list_url(config: &BucketConfig, params: &ListQueryParams) -> String {
    // Unreserved per RFC 3986; everything else (including `/`) is encoded.
    const QUERY_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    let enc = |s: &str| percent_encoding::utf8_percent_encode(s, QUERY_SET).to_string();

    let base = config
        .option("endpoint")
        .unwrap_or("")
        .trim_end_matches('/');
    let bucket = config.option("bucket_name").unwrap_or("");
    let mut url = if bucket.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{bucket}")
    };

    let mut pairs: Vec<String> = Vec::new();
    if params.is_v2 {
        pairs.push("list-type=2".to_string());
    }
    let full_prefix = build_list_prefix(config, &params.prefix);
    if !full_prefix.is_empty() {
        pairs.push(format!("prefix={}", enc(&full_prefix)));
    }
    if !params.delimiter.is_empty() {
        pairs.push(format!("delimiter={}", enc(&params.delimiter)));
    }
    pairs.push(format!("max-keys={}", params.max_keys));
    if let Some(token) = &params.continuation_token {
        pairs.push(format!("continuation-token={}", enc(token)));
    }
    if let Some(sa) = &params.start_after {
        pairs.push(format!(
            "start-after={}",
            enc(&build_list_prefix(config, sa))
        ));
    }
    if let Some(marker) = &params.marker {
        pairs.push(format!(
            "marker={}",
            enc(&build_list_prefix(config, marker))
        ));
    }

    if !pairs.is_empty() {
        url.push('?');
        url.push_str(&pairs.join("&"));
    }
    url
}

/// Version-agnostic parts of an S3 list response, shared by the V1 and V2
/// builders (which differ only in their pagination fields). Keys and prefixes
/// are already rewritten and URL-encoded; `prefix_value` is the raw echoed
/// request prefix, left for the caller to encode alongside its own fields.
struct ListEntries {
    contents: Vec<ListContents>,
    common_prefixes: Vec<ListCommonPrefix>,
    prefix_value: String,
    url_encode: bool,
}

/// URL-encode `s` per S3's RFC 3986 rules (unreserved chars + `/` left raw)
/// when `url_encode` is set; otherwise return it unchanged.
fn s3_encode(s: String, url_encode: bool) -> String {
    if !url_encode {
        return s;
    }
    // Unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
    const S3_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~')
        .remove(b'/');
    percent_encoding::utf8_percent_encode(&s, S3_ENCODE_SET).to_string()
}

/// Filter directory markers, rewrite keys/prefixes, and URL-encode the parts of
/// a list response that don't depend on the list-type version.
fn collect_list_entries(
    client_prefix: &str,
    encoding_type: &Option<String>,
    list_result: &BackendListResult,
    config: &BucketConfig,
    list_rewrite: Option<&ListRewrite>,
) -> ListEntries {
    let backend_prefix = config
        .backend_prefix
        .as_deref()
        .unwrap_or("")
        .trim_end_matches('/');
    let strip_prefix = if backend_prefix.is_empty() {
        String::new()
    } else {
        format!("{}/", backend_prefix)
    };

    // Filter out S3 directory marker objects — 0-byte objects created by the
    // S3 console (or similar tools) to represent "folders". Their key has a
    // trailing `/` that would otherwise leak into results as a phantom file.
    // We compare on the slash-trimmed key and detect them in three ways:
    //
    // 1. The marker matches a common prefix (e.g. key `photos/` collides with
    //    CommonPrefix `photos/`).
    // 2. The marker equals the backend prefix itself (the root directory marker
    //    for the entire backend prefix).
    // 3. The marker equals the full listing prefix (backend_prefix +
    //    client_prefix, minus trailing `/`). This is the most common real-world
    //    case: listing "harvard-lil/staging-gov-data/" returns a 0-byte key
    //    "harvard-lil/staging-gov-data/".
    let common_prefix_set: HashSet<&str> = list_result
        .common_prefixes
        .iter()
        .map(|p| p.trim_end_matches('/'))
        .collect();

    let full_list_prefix = format!("{}{}", strip_prefix, client_prefix);
    let list_prefix_trimmed = full_list_prefix.trim_end_matches('/');

    let is_directory_marker = |obj: &BackendObject| -> bool {
        let loc = obj.key.trim_end_matches('/');
        obj.size == 0
            && (common_prefix_set.contains(loc)
                || loc == backend_prefix
                || loc == list_prefix_trimmed)
    };

    let url_encode = matches!(encoding_type, Some(t) if t == "url");

    let contents: Vec<ListContents> = list_result
        .objects
        .iter()
        .filter(|obj| !is_directory_marker(obj))
        .map(|obj| ListContents {
            // Key preserved verbatim (empty path segments intact), then rewritten
            // and encoded per the client's request.
            key: s3_encode(
                rewrite_key(&obj.key, &strip_prefix, list_rewrite),
                url_encode,
            ),
            last_modified: obj.last_modified.clone(),
            etag: obj.etag.clone(),
            size: obj.size,
            storage_class: "STANDARD",
        })
        .collect();

    let common_prefixes: Vec<ListCommonPrefix> = list_result
        .common_prefixes
        .iter()
        .map(|raw_prefix| ListCommonPrefix {
            // Backend common prefixes already carry their trailing `/`.
            prefix: s3_encode(
                rewrite_key(raw_prefix, &strip_prefix, list_rewrite),
                url_encode,
            ),
        })
        .collect();

    let prefix_value = match list_rewrite {
        Some(rewrite) if !rewrite.add_prefix.is_empty() => {
            format!("{}{}", rewrite.add_prefix, client_prefix)
        }
        _ => client_prefix.to_string(),
    };

    ListEntries {
        contents,
        common_prefixes,
        prefix_value,
        url_encode,
    }
}

/// Build S3 ListObjectsV2 XML from an object_store ListResult.
///
/// Pagination is handled by the backend — `is_truncated` and
/// `next_continuation_token` are passed through from the backend's response.
pub(crate) fn build_list_xml(
    params: &ListXmlParams<'_>,
    list_result: &BackendListResult,
    config: &BucketConfig,
    list_rewrite: Option<&ListRewrite>,
) -> Result<String, ProxyError> {
    let ListEntries {
        contents,
        common_prefixes,
        prefix_value,
        url_encode,
    } = collect_list_entries(
        params.client_prefix,
        params.encoding_type,
        list_result,
        config,
        list_rewrite,
    );

    Ok(ListBucketResult {
        xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
        name: params.bucket_name.to_string(),
        prefix: s3_encode(prefix_value, url_encode),
        delimiter: s3_encode(params.delimiter.to_string(), url_encode),
        encoding_type: params.encoding_type.clone(),
        max_keys: params.max_keys,
        is_truncated: params.is_truncated,
        key_count: params.key_count,
        start_after: params
            .start_after
            .as_ref()
            .map(|s| s3_encode(s.clone(), url_encode)),
        continuation_token: params.continuation_token.clone(),
        next_continuation_token: params.next_continuation_token.clone(),
        contents,
        common_prefixes,
    }
    .to_xml())
}

/// Parameters for building the S3 ListObjectsV1 XML response.
pub(crate) struct ListXmlParamsV1<'a> {
    pub bucket_name: &'a str,
    pub client_prefix: &'a str,
    pub delimiter: &'a str,
    pub max_keys: usize,
    pub is_truncated: bool,
    pub marker: &'a str,
    pub next_marker: Option<String>,
    pub encoding_type: &'a Option<String>,
}

/// Build S3 ListObjectsV1 XML from an object_store ListResult.
pub(crate) fn build_list_xml_v1(
    params: &ListXmlParamsV1<'_>,
    list_result: &BackendListResult,
    config: &BucketConfig,
    list_rewrite: Option<&ListRewrite>,
) -> Result<String, ProxyError> {
    let ListEntries {
        contents,
        common_prefixes,
        prefix_value,
        url_encode,
    } = collect_list_entries(
        params.client_prefix,
        params.encoding_type,
        list_result,
        config,
        list_rewrite,
    );

    Ok(ListBucketResultV1 {
        xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
        name: params.bucket_name.to_string(),
        prefix: s3_encode(prefix_value, url_encode),
        delimiter: s3_encode(params.delimiter.to_string(), url_encode),
        encoding_type: params.encoding_type.clone(),
        max_keys: params.max_keys,
        is_truncated: params.is_truncated,
        marker: params.marker.to_string(),
        next_marker: params.next_marker.clone(),
        contents,
        common_prefixes,
    }
    .to_xml())
}

/// Apply strip/add prefix rewriting to a key or prefix value.
///
/// Works with `&str` slices to avoid intermediate allocations — only allocates
/// the final `String` once.
fn rewrite_key(raw: &str, strip_prefix: &str, list_rewrite: Option<&ListRewrite>) -> String {
    // Strip the backend prefix (borrow from `raw`, no allocation)
    let key = if !strip_prefix.is_empty() {
        raw.strip_prefix(strip_prefix).unwrap_or(raw)
    } else {
        raw
    };

    // Apply list_rewrite if present
    if let Some(rewrite) = list_rewrite {
        let key = if !rewrite.strip_prefix.is_empty() {
            key.strip_prefix(rewrite.strip_prefix.as_str())
                .unwrap_or(key)
        } else {
            key
        };

        if !rewrite.add_prefix.is_empty() {
            // Must allocate for add_prefix — early return
            return if key.is_empty() || key.starts_with('/') || rewrite.add_prefix.ends_with('/') {
                format!("{}{}", rewrite.add_prefix, key)
            } else {
                format!("{}/{}", rewrite.add_prefix, key)
            };
        }

        return key.to_string();
    }

    key.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `BackendListResult`. `common_prefixes` are given without their
    /// trailing `/` for brevity; a real backend returns them slash-terminated,
    /// so we append it here to match.
    fn make_list_result(keys: &[&str], common_prefixes: &[&str]) -> BackendListResult {
        BackendListResult {
            objects: keys
                .iter()
                .map(|k| BackendObject {
                    key: k.to_string(),
                    last_modified: "2009-10-12T17:50:30.000Z".to_string(),
                    etag: "\"abc\"".to_string(),
                    size: 100,
                })
                .collect(),
            common_prefixes: common_prefixes.iter().map(|p| format!("{p}/")).collect(),
            is_truncated: false,
            next_continuation_token: None,
        }
    }

    fn make_config(backend_prefix: Option<&str>) -> BucketConfig {
        BucketConfig {
            name: "test-bucket".to_string(),
            backend_type: "s3".to_string(),
            backend_prefix: backend_prefix.map(|s| s.to_string()),
            anonymous_access: false,
            allowed_roles: vec![],
            backend_options: Default::default(),
        }
    }

    #[test]
    fn test_prefix_element_includes_add_prefix() {
        let config = make_config(None);
        let list_result = make_list_result(&["subdir/file.parquet"], &[]);
        let rewrite = ListRewrite {
            strip_prefix: String::new(),
            add_prefix: "product/".to_string(),
        };

        let params = ListXmlParams {
            bucket_name: "account",
            client_prefix: "subdir/",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, Some(&rewrite)).unwrap();

        // The <Prefix> element should include the add_prefix
        assert!(
            xml.contains("<Prefix>product/subdir/</Prefix>"),
            "Expected <Prefix>product/subdir/</Prefix> but got: {}",
            xml
        );
        // Keys should also have the prefix
        assert!(xml.contains("<Key>product/subdir/file.parquet</Key>"));
    }

    #[test]
    fn test_prefix_element_without_rewrite() {
        let config = make_config(None);
        let list_result = make_list_result(&["file.parquet"], &[]);

        let params = ListXmlParams {
            bucket_name: "my-bucket",
            client_prefix: "some-prefix/",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();

        // Without rewrite, prefix should be unchanged
        assert!(xml.contains("<Prefix>some-prefix/</Prefix>"));
    }

    #[test]
    fn test_common_prefixes_include_add_prefix() {
        let config = make_config(None);
        let list_result = make_list_result(&[], &["subdir"]);
        let rewrite = ListRewrite {
            strip_prefix: String::new(),
            add_prefix: "product/".to_string(),
        };

        let params = ListXmlParams {
            bucket_name: "account",
            client_prefix: "",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 0,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, Some(&rewrite)).unwrap();

        assert!(
            xml.contains("<Prefix>product/subdir/</Prefix>"),
            "Expected common prefix to include add_prefix but got: {}",
            xml
        );
    }

    #[test]
    fn test_encoding_type_url_encodes_keys_and_prefixes() {
        let config = make_config(None);
        let list_result = make_list_result(&["dir/file with spaces.txt"], &["dir/sub dir"]);
        let encoding_type = Some("url".to_string());

        let params = ListXmlParams {
            bucket_name: "my-bucket",
            client_prefix: "dir/",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 2,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &encoding_type,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();

        // EncodingType element should be present
        assert!(
            xml.contains("<EncodingType>url</EncodingType>"),
            "Missing EncodingType element: {}",
            xml
        );
        // Key: spaces encoded, but '/', '.', '-' preserved (RFC 3986 unreserved + '/')
        assert!(
            xml.contains("<Key>dir/file%20with%20spaces.txt</Key>"),
            "Key not encoded correctly: {}",
            xml
        );
        // CommonPrefix: spaces encoded, '/' preserved
        assert!(
            xml.contains("<Prefix>dir/sub%20dir/</Prefix>"),
            "CommonPrefix not encoded correctly: {}",
            xml
        );
        // Prefix: '/' preserved
        assert!(
            xml.contains("<Prefix>dir/</Prefix>")
                || xml.contains("<Prefix>dir/sub%20dir/</Prefix>"),
            "Prefix not encoded correctly: {}",
            xml
        );
        // Delimiter: '/' preserved
        assert!(
            xml.contains("<Delimiter>/</Delimiter>"),
            "Delimiter should not encode '/': {}",
            xml
        );
    }

    #[test]
    fn test_encoding_type_url_encodes_special_chars() {
        let config = make_config(None);
        // S3 docs example: test_file(3).png → test_file%283%29.png
        let list_result = make_list_result(&["test_file(3).png"], &[]);
        let encoding_type = Some("url".to_string());

        let params = ListXmlParams {
            bucket_name: "my-bucket",
            client_prefix: "",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &encoding_type,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();

        assert!(
            xml.contains("<Key>test_file%283%29.png</Key>"),
            "Expected S3-style encoding of parens: {}",
            xml
        );
    }

    #[test]
    fn test_no_encoding_type_leaves_keys_raw() {
        let config = make_config(None);
        let list_result = make_list_result(&["dir/file with spaces.txt"], &[]);

        let params = ListXmlParams {
            bucket_name: "my-bucket",
            client_prefix: "dir/",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();

        // No EncodingType element
        assert!(
            !xml.contains("<EncodingType>"),
            "EncodingType should not be present: {}",
            xml
        );
        // Key should NOT be URL-encoded (spaces are XML-safe)
        assert!(
            xml.contains("<Key>dir/file with spaces.txt</Key>"),
            "Key should be raw: {}",
            xml
        );
    }

    #[test]
    fn test_parse_list_query_params_encoding_type() {
        let params = parse_list_query_params(Some("list-type=2&encoding-type=url&prefix=test/"));
        assert_eq!(params.encoding_type, Some("url".to_string()));
        assert_eq!(params.prefix, "test/");

        let params = parse_list_query_params(Some("list-type=2&prefix=test/"));
        assert_eq!(params.encoding_type, None);
    }

    #[test]
    fn test_parse_list_query_params_v1_vs_v2() {
        // V2: list-type=2 present
        let params = parse_list_query_params(Some("list-type=2&prefix=test/"));
        assert!(params.is_v2);
        assert_eq!(params.marker, None);

        // V1: no list-type param
        let params = parse_list_query_params(Some("prefix=test/&marker=key123"));
        assert!(!params.is_v2);
        assert_eq!(params.marker, Some("key123".to_string()));

        // V1: list-type=1 (not 2)
        let params = parse_list_query_params(Some("list-type=1&marker=abc"));
        assert!(!params.is_v2);
        assert_eq!(params.marker, Some("abc".to_string()));

        // No query string at all → V1 default
        let params = parse_list_query_params(None);
        assert!(!params.is_v2);
        assert_eq!(params.marker, None);
    }

    #[test]
    fn test_build_list_xml_v1_basic() {
        let config = make_config(None);
        let list_result = make_list_result(&["photos/image.jpg"], &["photos/thumbs"]);

        let params = ListXmlParamsV1 {
            bucket_name: "my-bucket",
            client_prefix: "photos/",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            marker: "photos/abc.jpg",
            next_marker: None,
            encoding_type: &None,
        };

        let xml = build_list_xml_v1(&params, &list_result, &config, None).unwrap();

        // V1 elements present
        assert!(
            xml.contains("<Marker>photos/abc.jpg</Marker>"),
            "Missing Marker: {xml}"
        );
        assert!(xml.contains("<Name>my-bucket</Name>"));
        assert!(xml.contains("<Prefix>photos/</Prefix>"));
        assert!(xml.contains("<Key>photos/image.jpg</Key>"));
        assert!(xml.contains("<CommonPrefixes><Prefix>photos/thumbs/</Prefix></CommonPrefixes>"));

        // V2 elements must NOT be present
        assert!(
            !xml.contains("<KeyCount>"),
            "V1 should not have KeyCount: {xml}"
        );
        assert!(
            !xml.contains("<StartAfter>"),
            "V1 should not have StartAfter: {xml}"
        );
        assert!(
            !xml.contains("<ContinuationToken>"),
            "V1 should not have ContinuationToken: {xml}"
        );
        assert!(
            !xml.contains("<NextMarker>"),
            "NextMarker should be absent when not truncated: {xml}"
        );
    }

    #[test]
    fn test_build_list_xml_v1_truncated_with_next_marker() {
        let config = make_config(None);
        let list_result = make_list_result(&["a.txt", "b.txt"], &[]);

        let params = ListXmlParamsV1 {
            bucket_name: "bucket",
            client_prefix: "",
            delimiter: "/",
            max_keys: 2,
            is_truncated: true,
            marker: "",
            next_marker: Some("b.txt".to_string()),
            encoding_type: &None,
        };

        let xml = build_list_xml_v1(&params, &list_result, &config, None).unwrap();

        assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
        assert!(
            xml.contains("<NextMarker>b.txt</NextMarker>"),
            "Expected NextMarker: {xml}"
        );
        assert!(xml.contains("<Marker></Marker>") || xml.contains("<Marker/>"));
    }

    /// Create a `BackendListResult` with objects that have explicit sizes and
    /// raw keys, for testing directory marker filtering. Keys are passed exactly
    /// as the backend would return them (directory markers keep their trailing
    /// `/`); common prefixes get a trailing `/` appended.
    fn make_list_result_with_sizes(
        objects: &[(&str, u64)],
        common_prefixes: &[&str],
    ) -> BackendListResult {
        BackendListResult {
            objects: objects
                .iter()
                .map(|(k, size)| BackendObject {
                    key: k.to_string(),
                    last_modified: "2009-10-12T17:50:30.000Z".to_string(),
                    etag: "\"abc\"".to_string(),
                    size: *size,
                })
                .collect(),
            common_prefixes: common_prefixes.iter().map(|p| format!("{p}/")).collect(),
            is_truncated: false,
            next_continuation_token: None,
        }
    }

    #[test]
    fn test_directory_markers_filtered_from_v2_contents() {
        let config = make_config(None);
        // A 0-byte marker key "photos/" (the backend returns it slash-terminated)
        // alongside the "photos" common prefix, plus a real file.
        let list_result =
            make_list_result_with_sizes(&[("photos/", 0), ("readme.txt", 42)], &["photos"]);

        let params = ListXmlParams {
            bucket_name: "my-bucket",
            client_prefix: "",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();

        // The directory marker should NOT appear in Contents
        assert!(
            !xml.contains("<Key>photos/</Key>") && !xml.contains("<Key>photos</Key>"),
            "Directory marker should be filtered out: {xml}"
        );
        // The real file should still be present
        assert!(
            xml.contains("<Key>readme.txt</Key>"),
            "Real file should remain: {xml}"
        );
        // The common prefix should still be present
        assert!(
            xml.contains("<Prefix>photos/</Prefix>"),
            "Common prefix should remain: {xml}"
        );
    }

    #[test]
    fn test_zero_byte_file_not_filtered_when_no_matching_prefix() {
        let config = make_config(None);
        // A 0-byte file that does NOT match any common prefix should be kept.
        let list_result = make_list_result_with_sizes(&[("empty.txt", 0)], &[]);

        let params = ListXmlParams {
            bucket_name: "my-bucket",
            client_prefix: "",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();

        assert!(
            xml.contains("<Key>empty.txt</Key>"),
            "Zero-byte file without matching prefix should be kept: {xml}"
        );
    }

    #[test]
    fn test_directory_markers_filtered_from_v1_contents() {
        let config = make_config(None);
        let list_result =
            make_list_result_with_sizes(&[("photos/", 0), ("readme.txt", 42)], &["photos"]);

        let params = ListXmlParamsV1 {
            bucket_name: "my-bucket",
            client_prefix: "",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            marker: "",
            next_marker: None,
            encoding_type: &None,
        };

        let xml = build_list_xml_v1(&params, &list_result, &config, None).unwrap();

        assert!(
            !xml.contains("<Key>photos/</Key>") && !xml.contains("<Key>photos</Key>"),
            "Directory marker should be filtered out in V1: {xml}"
        );
        assert!(
            xml.contains("<Key>readme.txt</Key>"),
            "Real file should remain in V1: {xml}"
        );
    }

    #[test]
    fn test_directory_marker_at_list_prefix_filtered_v2() {
        // Reproduces the real-world bug from source-cooperative/source.coop#245:
        //
        // Backend bucket: us-west-2.opendata.source.coop
        // backend_prefix: "harvard-lil/" (the account-level prefix)
        // Client lists with prefix: "staging-gov-data/"
        // Full S3 prefix sent: "harvard-lil/staging-gov-data/"
        //
        // S3 returns a 0-byte key "harvard-lil/staging-gov-data/" in Contents
        // (the directory marker). After strip_prefix ("harvard-lil/"), this
        // would become "staging-gov-data/" — a phantom file that should not
        // appear in the listing.
        let config = make_config(Some("harvard-lil"));
        let list_result = make_list_result_with_sizes(
            &[
                ("harvard-lil/staging-gov-data/", 0),
                ("harvard-lil/staging-gov-data/data/file.parquet", 1000),
            ],
            &["harvard-lil/staging-gov-data/data"],
        );

        let params = ListXmlParams {
            bucket_name: "harvard-lil",
            client_prefix: "staging-gov-data/",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();

        // The directory marker should NOT appear in Contents
        assert!(
            !xml.contains("<Key>staging-gov-data/</Key>")
                && !xml.contains("<Key>staging-gov-data</Key>"),
            "Directory marker at list prefix should be filtered out: {xml}"
        );
        // The real file should still appear (with prefix stripped)
        assert!(
            xml.contains("<Key>staging-gov-data/data/file.parquet</Key>"),
            "Real file should remain: {xml}"
        );
        // The common prefix should still appear
        assert!(
            xml.contains("<Prefix>staging-gov-data/data/</Prefix>"),
            "Common prefix should remain: {xml}"
        );
    }

    #[test]
    fn test_directory_marker_at_list_prefix_filtered_v1() {
        // Same scenario as V2 test above, but for ListObjectsV1.
        let config = make_config(Some("harvard-lil"));
        let list_result = make_list_result_with_sizes(
            &[
                ("harvard-lil/staging-gov-data/", 0),
                ("harvard-lil/staging-gov-data/data/file.parquet", 1000),
            ],
            &["harvard-lil/staging-gov-data/data"],
        );

        let params = ListXmlParamsV1 {
            bucket_name: "harvard-lil",
            client_prefix: "staging-gov-data/",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            marker: "",
            next_marker: None,
            encoding_type: &None,
        };

        let xml = build_list_xml_v1(&params, &list_result, &config, None).unwrap();

        assert!(
            !xml.contains("<Key>staging-gov-data/</Key>")
                && !xml.contains("<Key>staging-gov-data</Key>"),
            "Directory marker at list prefix should be filtered out in V1: {xml}"
        );
        assert!(
            xml.contains("<Key>staging-gov-data/data/file.parquet</Key>"),
            "Real file should remain in V1: {xml}"
        );
    }

    #[test]
    fn test_nonzero_byte_object_matching_prefix_not_filtered() {
        let config = make_config(None);
        // An object with size > 0 that happens to match a common prefix
        // should NOT be filtered — only 0-byte markers are filtered.
        let list_result = make_list_result_with_sizes(&[("photos", 100)], &["photos"]);

        let params = ListXmlParams {
            bucket_name: "my-bucket",
            client_prefix: "",
            delimiter: "/",
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();

        assert!(
            xml.contains("<Key>photos</Key>"),
            "Non-zero-byte object should not be filtered: {xml}"
        );
    }

    // -- Empty path segments (issue #116) ------------------------------------

    #[test]
    fn parse_backend_list_xml_preserves_empty_path_segments() {
        // A legal S3 key with a `//` — object_store::Path would reject this and
        // fail the whole page. We must keep it verbatim.
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
            <ListBucketResult>
              <IsTruncated>false</IsTruncated>
              <Contents>
                <Key>raw//b.e21.nc</Key>
                <LastModified>2009-10-12T17:50:30.000Z</LastModified>
                <ETag>"abc"</ETag>
                <Size>42</Size>
              </Contents>
              <Contents>
                <Key>raw/valid.nc</Key>
                <LastModified>2009-10-12T17:50:30.000Z</LastModified>
                <ETag>"def"</ETag>
                <Size>7</Size>
              </Contents>
            </ListBucketResult>"#;

        let result = parse_backend_list_xml(xml).unwrap();
        assert_eq!(result.objects.len(), 2);
        assert_eq!(result.objects[0].key, "raw//b.e21.nc");
        assert_eq!(result.objects[0].size, 42);
        assert_eq!(result.objects[1].key, "raw/valid.nc");
        assert!(!result.is_truncated);
    }

    #[test]
    fn empty_path_segment_key_survives_to_xml() {
        // End-to-end: a `//` key must appear verbatim in the response the client
        // sees, not 503 the whole prefix.
        let config = make_config(None);
        let list_result = make_list_result(&["raw//b.e21.nc", "raw/valid.nc"], &[]);

        let params = ListXmlParams {
            bucket_name: "my-bucket",
            client_prefix: "raw/",
            delimiter: "",
            max_keys: 1000,
            is_truncated: false,
            key_count: 2,
            start_after: &None,
            continuation_token: &None,
            next_continuation_token: None,
            encoding_type: &None,
        };

        let xml = build_list_xml(&params, &list_result, &config, None).unwrap();
        assert!(
            xml.contains("<Key>raw//b.e21.nc</Key>"),
            "Empty path segment key must pass through verbatim: {xml}"
        );
        assert!(xml.contains("<Key>raw/valid.nc</Key>"));
    }

    #[test]
    fn build_backend_list_url_maps_prefix_and_encodes() {
        let mut config = make_config(Some("harvard-lil"));
        config
            .backend_options
            .insert("endpoint".into(), "https://s3.example.com".into());
        config
            .backend_options
            .insert("bucket_name".into(), "backend-bucket".into());
        let params = parse_list_query_params(Some(
            "list-type=2&prefix=staging gov/&delimiter=/&max-keys=50&encoding-type=url",
        ));
        let url = build_backend_list_url(&config, &params);

        // Backend prefix is prepended, space is %20 (not `+`) for SigV4, `/`
        // encoded in values, and encoding-type is NOT forwarded.
        assert!(
            url.starts_with("https://s3.example.com/backend-bucket?"),
            "{url}"
        );
        assert!(url.contains("list-type=2"), "{url}");
        assert!(
            url.contains("prefix=harvard-lil%2Fstaging%20gov%2F"),
            "{url}"
        );
        assert!(url.contains("delimiter=%2F"), "{url}");
        assert!(url.contains("max-keys=50"), "{url}");
        assert!(!url.contains("encoding-type"), "{url}");
    }
}
