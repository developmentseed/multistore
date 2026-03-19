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
}

/// All query parameters needed for a LIST operation, parsed in a single pass.
pub struct ListQueryParams {
    pub prefix: String,
    pub delimiter: String,
    pub max_keys: usize,
    pub continuation_token: Option<String>,
    pub start_after: Option<String>,
}

/// Parse prefix, delimiter, and pagination params from a LIST query string in one pass.
pub fn parse_list_query_params(raw_query: Option<&str>) -> ListQueryParams {
    let mut prefix = None;
    let mut delimiter = None;
    let mut max_keys = None;
    let mut continuation_token = None;
    let mut start_after = None;

    if let Some(q) = raw_query {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            match k.as_ref() {
                "prefix" => prefix = Some(v.into_owned()),
                "delimiter" => delimiter = Some(v.into_owned()),
                "max-keys" => max_keys = Some(v.into_owned()),
                "continuation-token" => continuation_token = Some(v.into_owned()),
                "start-after" => start_after = Some(v.into_owned()),
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

    let contents: Vec<ListContents> = list_result
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

    let common_prefixes: Vec<ListCommonPrefix> = list_result
        .common_prefixes
        .iter()
        .map(|p| {
            let raw_prefix = format!("{}/", p);
            ListCommonPrefix {
                prefix: rewrite_key(&raw_prefix, &strip_prefix, list_rewrite),
            }
        })
        .collect();

    Ok(ListBucketResult {
        xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
        name: params.bucket_name.to_string(),
        prefix: match list_rewrite {
            Some(rewrite) if !rewrite.add_prefix.is_empty() => {
                format!("{}{}", rewrite.add_prefix, params.client_prefix)
            }
            _ => params.client_prefix.to_string(),
        },
        delimiter: params.delimiter.to_string(),
        max_keys: params.max_keys,
        is_truncated: params.is_truncated,
        key_count: params.key_count,
        start_after: params.start_after.clone(),
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
        };

        let xml = build_list_xml(&params, &list_result, &config, Some(&rewrite)).unwrap();

        assert!(
            xml.contains("<Prefix>product/subdir/</Prefix>"),
            "Expected common prefix to include add_prefix but got: {}",
            xml
        );
    }
}
