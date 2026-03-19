//! LIST-specific helpers for building S3 ListObjectsV2 XML responses.
//!
//! Extracted from `proxy.rs` to keep the gateway focused on orchestration.

use crate::api::list_rewrite::ListRewrite;
use crate::api::response::{ListBucketResult, ListCommonPrefix, ListContents};
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
    /// Opaque token for fetching the next page of results.
    pub continuation_token: Option<String>,
    /// Return keys lexicographically after this value.
    pub start_after: Option<String>,
    /// Encoding type for keys/prefixes in the response (e.g. "url").
    pub encoding_type: Option<String>,
}

/// Parse prefix, delimiter, and pagination params from a LIST query string in one pass.
pub fn parse_list_query_params(raw_query: Option<&str>) -> ListQueryParams {
    let mut prefix = None;
    let mut delimiter = None;
    let mut max_keys = None;
    let mut continuation_token = None;
    let mut start_after = None;
    let mut encoding_type = None;

    if let Some(q) = raw_query {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            match k.as_ref() {
                "prefix" => prefix = Some(v.into_owned()),
                "delimiter" => delimiter = Some(v.into_owned()),
                "max-keys" => max_keys = Some(v.into_owned()),
                "continuation-token" => continuation_token = Some(v.into_owned()),
                "start-after" => start_after = Some(v.into_owned()),
                "encoding-type" => encoding_type = Some(v.into_owned()),
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

/// Build S3 ListObjectsV2 XML from an object_store ListResult.
///
/// Pagination is handled by the backend — `is_truncated` and
/// `next_continuation_token` are passed through from the backend's response.
pub(crate) fn build_list_xml(
    params: &ListXmlParams<'_>,
    list_result: &object_store::ListResult,
    config: &BucketConfig,
    list_rewrite: Option<&ListRewrite>,
) -> Result<String, ProxyError> {
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

    let mut contents: Vec<ListContents> = list_result
        .objects
        .iter()
        .map(|obj| {
            let raw_key = obj.location.to_string();
            ListContents {
                key: rewrite_key(&raw_key, &strip_prefix, list_rewrite),
                last_modified: obj
                    .last_modified
                    .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                    .to_string(),
                etag: obj.e_tag.as_deref().unwrap_or("\"\"").to_string(),
                size: obj.size,
                storage_class: "STANDARD",
            }
        })
        .collect();

    let mut common_prefixes: Vec<ListCommonPrefix> = list_result
        .common_prefixes
        .iter()
        .map(|p| {
            let raw_prefix = format!("{}/", p);
            ListCommonPrefix {
                prefix: rewrite_key(&raw_prefix, &strip_prefix, list_rewrite),
            }
        })
        .collect();

    let url_encode = matches!(params.encoding_type, Some(ref t) if t == "url");
    let encode = |s: String| -> String {
        if url_encode {
            // S3 URL-encodes per RFC 3986: leave unreserved chars + '/' unencoded.
            // Unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
            const S3_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
                .remove(b'-')
                .remove(b'.')
                .remove(b'_')
                .remove(b'~')
                .remove(b'/');
            percent_encoding::utf8_percent_encode(&s, S3_ENCODE_SET).to_string()
        } else {
            s
        }
    };

    let prefix_value = match list_rewrite {
        Some(rewrite) if !rewrite.add_prefix.is_empty() => {
            format!("{}{}", rewrite.add_prefix, params.client_prefix)
        }
        _ => params.client_prefix.to_string(),
    };

    // URL-encode keys, prefixes, and delimiter when encoding-type=url
    if url_encode {
        for item in &mut contents {
            item.key = encode(std::mem::take(&mut item.key));
        }
        for cp in &mut common_prefixes {
            cp.prefix = encode(std::mem::take(&mut cp.prefix));
        }
    }

    Ok(ListBucketResult {
        xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
        name: params.bucket_name.to_string(),
        prefix: encode(prefix_value),
        delimiter: encode(params.delimiter.to_string()),
        encoding_type: params.encoding_type.clone(),
        max_keys: params.max_keys,
        is_truncated: params.is_truncated,
        key_count: params.key_count,
        start_after: params.start_after.as_ref().map(|s| encode(s.clone())),
        continuation_token: params.continuation_token.clone(),
        next_continuation_token: params.next_continuation_token.clone(),
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
    use chrono::Utc;
    use object_store::{path::Path, ListResult, ObjectMeta};

    fn make_list_result(keys: &[&str], common_prefixes: &[&str]) -> ListResult {
        ListResult {
            objects: keys
                .iter()
                .map(|k| ObjectMeta {
                    location: Path::from(*k),
                    last_modified: Utc::now(),
                    size: 100,
                    e_tag: Some("\"abc\"".to_string()),
                    version: None,
                })
                .collect(),
            common_prefixes: common_prefixes.iter().map(|p| Path::from(*p)).collect(),
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
}
