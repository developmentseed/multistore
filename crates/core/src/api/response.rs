//! S3 XML response serialization.

use quick_xml::se::to_string as xml_to_string;
use serde::Serialize;

use crate::error::ProxyError;
pub use crate::types::BucketOwner;

/// S3 Error response XML.
#[derive(Debug, Serialize)]
#[serde(rename = "Error")]
pub struct ErrorResponse {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
    #[serde(rename = "Resource")]
    pub resource: String,
    #[serde(rename = "RequestId")]
    pub request_id: String,
}

impl ErrorResponse {
    /// Build an S3-compatible error response.
    ///
    /// When `debug` is `true`, the full internal error message is included
    /// (useful during development). When `false`, server-side errors (500)
    /// use a generic message to avoid leaking backend details.
    pub fn from_proxy_error(
        err: &ProxyError,
        resource: &str,
        request_id: &str,
        debug: bool,
    ) -> Self {
        let message = if debug {
            err.to_string()
        } else {
            err.safe_message()
        };
        Self {
            code: err.s3_error_code().to_string(),
            message,
            resource: resource.to_string(),
            request_id: request_id.to_string(),
        }
    }

    /// Build an S3 `SlowDown` error for rate-limited requests.
    pub fn slow_down(request_id: &str) -> Self {
        Self {
            code: "SlowDown".to_string(),
            message: "Please reduce your request rate.".to_string(),
            resource: String::new(),
            request_id: request_id.to_string(),
        }
    }

    /// Serialize this error response to an S3-compatible XML string.
    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            xml_to_string(self)
                .unwrap_or_else(|_| "<Error><Code>InternalError</Code></Error>".to_string())
        )
    }
}

/// InitiateMultipartUpload response.
#[derive(Debug, Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
pub struct InitiateMultipartUploadResult {
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
}

impl InitiateMultipartUploadResult {
    /// Serialize this result to an S3-compatible XML string.
    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            xml_to_string(self).unwrap_or_default()
        )
    }
}

/// CompleteMultipartUpload response.
#[derive(Debug, Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
pub struct CompleteMultipartUploadResult {
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

impl CompleteMultipartUploadResult {
    /// Serialize this result to an S3-compatible XML string.
    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            xml_to_string(self).unwrap_or_default()
        )
    }
}

/// Deserialized XML body of a CompleteMultipartUpload request.
#[derive(Debug, serde::Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
pub struct CompleteMultipartUploadRequest {
    #[serde(rename = "Part")]
    pub parts: Vec<CompletePart>,
}

/// A single part entry in a CompleteMultipartUpload request.
#[derive(Debug, serde::Deserialize)]
pub struct CompletePart {
    /// The part number assigned during UploadPart.
    #[serde(rename = "PartNumber")]
    pub part_number: u32,
    /// The ETag returned by the backend for this part.
    #[serde(rename = "ETag")]
    pub etag: String,
}

/// ListAllMyBucketsResult response (for `GET /`).
#[derive(Debug, Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
pub struct ListAllMyBucketsResult {
    #[serde(rename = "Owner")]
    pub owner: BucketOwner,
    #[serde(rename = "Buckets")]
    pub buckets: BucketList,
}

/// Wrapper for the `<Buckets>` element in a ListAllMyBucketsResult response.
#[derive(Debug, Serialize)]
pub struct BucketList {
    #[serde(rename = "Bucket")]
    pub buckets: Vec<BucketEntry>,
}

/// A single bucket entry in a ListAllMyBucketsResult response.
#[derive(Debug, Serialize)]
pub struct BucketEntry {
    /// The virtual bucket name.
    #[serde(rename = "Name")]
    pub name: String,
    /// ISO 8601 creation timestamp.
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
}

impl ListAllMyBucketsResult {
    /// Serialize this result to an S3-compatible XML string.
    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            xml_to_string(self).unwrap_or_default()
        )
    }
}

/// S3 ListObjectsV2 response.
#[derive(Debug, Serialize)]
#[serde(rename = "ListBucketResult")]
pub struct ListBucketResult {
    /// XML namespace URI for the S3 ListBucketResult schema.
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    /// The bucket name.
    #[serde(rename = "Name")]
    pub name: String,
    /// The key prefix used to filter results.
    #[serde(rename = "Prefix")]
    pub prefix: String,
    /// The delimiter used to group common prefixes.
    #[serde(rename = "Delimiter", skip_serializing_if = "String::is_empty")]
    pub delimiter: String,
    /// Encoding type applied to keys and prefixes in this response.
    #[serde(rename = "EncodingType", skip_serializing_if = "Option::is_none")]
    pub encoding_type: Option<String>,
    /// Maximum number of keys returned per page.
    #[serde(rename = "MaxKeys")]
    pub max_keys: usize,
    /// Whether additional pages of results are available.
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    /// Number of keys returned in this response (contents + common prefixes).
    #[serde(rename = "KeyCount")]
    pub key_count: usize,
    /// The `start-after` value from the request, if provided.
    #[serde(rename = "StartAfter", skip_serializing_if = "Option::is_none")]
    pub start_after: Option<String>,
    /// The continuation token from the request, echoed back.
    #[serde(rename = "ContinuationToken", skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
    /// Token to pass in the next request to fetch the next page.
    #[serde(
        rename = "NextContinuationToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_continuation_token: Option<String>,
    /// The object entries matching the list request.
    #[serde(rename = "Contents", default)]
    pub contents: Vec<ListContents>,
    /// Common prefix entries when a delimiter is used.
    #[serde(rename = "CommonPrefixes", default)]
    pub common_prefixes: Vec<ListCommonPrefix>,
}

/// A single object entry in a ListObjectsV2 response.
#[derive(Debug, Clone, Serialize)]
pub struct ListContents {
    /// The object key.
    #[serde(rename = "Key")]
    pub key: String,
    /// ISO 8601 timestamp of the last modification.
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    /// The entity tag (ETag) for the object.
    #[serde(rename = "ETag")]
    pub etag: String,
    /// Object size in bytes.
    #[serde(rename = "Size")]
    pub size: u64,
    /// Storage class of the object (always "STANDARD" in this proxy).
    #[serde(rename = "StorageClass")]
    pub storage_class: &'static str,
}

/// A common prefix entry in a ListObjectsV2 response (delimiter-based grouping).
#[derive(Debug, Serialize)]
pub struct ListCommonPrefix {
    /// The shared prefix for grouped keys.
    #[serde(rename = "Prefix")]
    pub prefix: String,
}

impl ListBucketResult {
    /// Serialize this result to an S3-compatible XML string.
    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
            xml_to_string(self).unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_bucket_result_xml() {
        let result = ListBucketResult {
            xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
            name: "my-bucket".to_string(),
            prefix: "photos/".to_string(),
            delimiter: "/".to_string(),
            encoding_type: None,
            max_keys: 1000,
            is_truncated: false,
            key_count: 1,
            start_after: None,
            continuation_token: None,
            next_continuation_token: None,
            contents: vec![ListContents {
                key: "photos/image.jpg".to_string(),
                last_modified: "2024-01-01T00:00:00.000Z".to_string(),
                etag: "\"abc123\"".to_string(),
                size: 1024,
                storage_class: "STANDARD",
            }],
            common_prefixes: vec![ListCommonPrefix {
                prefix: "photos/thumbs/".to_string(),
            }],
        };

        let xml = result.to_xml();
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(
            xml.contains("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">")
        );
        assert!(xml.contains("<Name>my-bucket</Name>"));
        assert!(xml.contains("<Key>photos/image.jpg</Key>"));
        assert!(xml.contains("<Size>1024</Size>"));
        assert!(xml.contains("<CommonPrefixes><Prefix>photos/thumbs/</Prefix></CommonPrefixes>"));
    }

    #[test]
    fn test_list_bucket_result_empty() {
        let result = ListBucketResult {
            xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
            name: "bucket".to_string(),
            prefix: String::new(),
            delimiter: "/".to_string(),
            encoding_type: None,
            max_keys: 1000,
            is_truncated: false,
            key_count: 0,
            start_after: None,
            continuation_token: None,
            next_continuation_token: None,
            contents: vec![],
            common_prefixes: vec![],
        };

        let xml = result.to_xml();
        assert!(xml.contains("<KeyCount>0</KeyCount>"));
        assert!(!xml.contains("<Contents>"));
        assert!(!xml.contains("<CommonPrefixes>"));
    }
}
