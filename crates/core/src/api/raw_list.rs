//! String-based list result types — no `object_store::path::Path` normalization.
//!
//! These types allow S3 keys with arbitrary characters (including `//`) to pass
//! through without being rejected or normalized by `Path::parse()` / `Path::from()`.

use chrono::{DateTime, Utc};
use serde::Deserialize;

/// String-based list result — avoids `Path` normalization.
pub struct RawListResult {
    /// Object metadata entries.
    pub objects: Vec<RawObjectMeta>,
    /// Common prefixes (including trailing `/`).
    pub common_prefixes: Vec<String>,
}

/// Metadata for a single object, using raw string keys.
pub struct RawObjectMeta {
    /// The full S3 key (may contain `//` or other characters that `Path` rejects).
    pub location: String,
    /// Last modification timestamp.
    pub last_modified: DateTime<Utc>,
    /// Object size in bytes.
    pub size: u64,
    /// Entity tag, if available.
    pub e_tag: Option<String>,
}

/// A paginated list result with an optional continuation token.
pub struct RawPaginatedListResult {
    /// The list result for this page.
    pub result: RawListResult,
    /// Token for fetching the next page, or `None` if this is the last page.
    pub page_token: Option<String>,
}

// ── S3 ListObjectsV2 XML deserialization ──────────────────────────────

/// Root element of a ListObjectsV2 response.
#[derive(Debug, Deserialize)]
#[serde(rename = "ListBucketResult")]
pub(crate) struct S3ListResponse {
    #[serde(rename = "IsTruncated", default)]
    pub is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    pub next_continuation_token: Option<String>,
    #[serde(rename = "Contents", default)]
    pub contents: Vec<S3Object>,
    #[serde(rename = "CommonPrefixes", default)]
    pub common_prefixes: Vec<S3CommonPrefix>,
}

/// A single `<Contents>` entry in the S3 XML response.
#[derive(Debug, Deserialize)]
pub(crate) struct S3Object {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "LastModified")]
    pub last_modified: DateTime<Utc>,
    #[serde(rename = "Size", default)]
    pub size: u64,
    #[serde(rename = "ETag")]
    pub e_tag: Option<String>,
}

/// A single `<CommonPrefixes>` entry in the S3 XML response.
#[derive(Debug, Deserialize)]
pub(crate) struct S3CommonPrefix {
    #[serde(rename = "Prefix")]
    pub prefix: String,
}

impl From<S3ListResponse> for RawPaginatedListResult {
    fn from(resp: S3ListResponse) -> Self {
        let page_token = if resp.is_truncated {
            resp.next_continuation_token
        } else {
            None
        };

        RawPaginatedListResult {
            result: RawListResult {
                objects: resp
                    .contents
                    .into_iter()
                    .map(|obj| RawObjectMeta {
                        location: obj.key,
                        last_modified: obj.last_modified,
                        size: obj.size,
                        e_tag: obj.e_tag,
                    })
                    .collect(),
                common_prefixes: resp
                    .common_prefixes
                    .into_iter()
                    .map(|cp| cp.prefix)
                    .collect(),
            },
            page_token,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_list_objects_v2_response() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix>media/</Prefix>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>abc123</NextContinuationToken>
  <Contents>
    <Key>media/file.txt</Key>
    <LastModified>2024-01-15T10:30:00.000Z</LastModified>
    <Size>1024</Size>
    <ETag>"abcdef"</ETag>
  </Contents>
  <Contents>
    <Key>media//nested/file.txt</Key>
    <LastModified>2024-02-20T08:00:00.000Z</LastModified>
    <Size>2048</Size>
    <ETag>"123456"</ETag>
  </Contents>
  <CommonPrefixes>
    <Prefix>media//</Prefix>
  </CommonPrefixes>
  <CommonPrefixes>
    <Prefix>media/subdir/</Prefix>
  </CommonPrefixes>
</ListBucketResult>"#;

        let resp: S3ListResponse = quick_xml::de::from_str(xml).unwrap();
        let result: RawPaginatedListResult = resp.into();

        assert_eq!(result.page_token, Some("abc123".to_string()));
        assert_eq!(result.result.objects.len(), 2);
        assert_eq!(result.result.objects[0].location, "media/file.txt");
        assert_eq!(result.result.objects[1].location, "media//nested/file.txt");
        assert_eq!(result.result.objects[0].size, 1024);
        assert_eq!(result.result.objects[1].size, 2048);
        assert_eq!(result.result.common_prefixes.len(), 2);
        assert_eq!(result.result.common_prefixes[0], "media//");
        assert_eq!(result.result.common_prefixes[1], "media/subdir/");
    }

    #[test]
    fn deserialize_empty_response() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix></Prefix>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;

        let resp: S3ListResponse = quick_xml::de::from_str(xml).unwrap();
        let result: RawPaginatedListResult = resp.into();

        assert!(result.page_token.is_none());
        assert!(result.result.objects.is_empty());
        assert!(result.result.common_prefixes.is_empty());
    }

    #[test]
    fn deserialize_not_truncated_ignores_continuation_token() {
        // Some S3-compatible backends may include NextContinuationToken even when
        // IsTruncated is false. We should ignore it.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix></Prefix>
  <IsTruncated>false</IsTruncated>
  <NextContinuationToken>stale-token</NextContinuationToken>
  <Contents>
    <Key>file.txt</Key>
    <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    <Size>100</Size>
  </Contents>
</ListBucketResult>"#;

        let resp: S3ListResponse = quick_xml::de::from_str(xml).unwrap();
        let result: RawPaginatedListResult = resp.into();

        assert!(result.page_token.is_none());
        assert_eq!(result.result.objects.len(), 1);
    }
}
