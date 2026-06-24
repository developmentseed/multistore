//! Batch delete (`DeleteObjects`) request/response handling.
//!
//! S3's batch delete (`POST /{bucket}?delete`) carries the keys to delete in an
//! XML request body and returns a per-key result. This module owns the pure
//! parsing and serialization: reading the inbound `<Delete>` body, building the
//! body forwarded to the backend, and merging the backend's `<DeleteResult>`
//! with the proxy's own per-key authorization decisions.
//!
//! Per-key authorization (via [`auth::key_authorized`](crate::auth::key_authorized))
//! and backend forwarding live in the gateway; everything here is runtime- and
//! I/O-free so it can be exercised directly in unit tests.

use crate::error::ProxyError;
use serde::{Deserialize, Serialize};

/// Parsed inbound `<Delete>` request body.
#[derive(Debug, Deserialize)]
#[serde(rename = "Delete")]
pub struct DeleteRequest {
    /// When true, successful deletions are omitted from the response — only
    /// errors are reported.
    #[serde(default, rename = "Quiet")]
    pub quiet: bool,
    /// The objects to delete.
    #[serde(default, rename = "Object")]
    pub objects: Vec<DeleteObjectEntry>,
}

/// A single `<Object>` entry in a batch-delete request.
#[derive(Debug, Deserialize)]
pub struct DeleteObjectEntry {
    /// The (client-facing) object key to delete.
    #[serde(rename = "Key")]
    pub key: String,
}

impl DeleteRequest {
    /// The maximum number of objects S3 accepts in a single batch delete.
    pub const MAX_KEYS: usize = 1000;

    /// Parse a batch-delete request body.
    ///
    /// Mirrors S3's `MalformedXML` rejections: the body must be well-formed XML,
    /// name at least one object, and name no more than [`MAX_KEYS`](Self::MAX_KEYS).
    pub fn parse(body: &[u8]) -> Result<Self, ProxyError> {
        let req: DeleteRequest = quick_xml::de::from_reader(body)
            .map_err(|e| ProxyError::MalformedXml(format!("malformed delete body: {e}")))?;
        if req.objects.is_empty() {
            return Err(ProxyError::MalformedXml(
                "delete request names no objects".into(),
            ));
        }
        if req.objects.len() > Self::MAX_KEYS {
            return Err(ProxyError::MalformedXml(format!(
                "delete request names {} objects, exceeding the {}-key limit",
                req.objects.len(),
                Self::MAX_KEYS
            )));
        }
        Ok(req)
    }

    /// The client-facing keys named in the request, in order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.objects.iter().map(|o| o.key.as_str())
    }
}

/// Build the `<Delete>` XML body forwarded to the backend.
///
/// `backend_keys` are the keys already mapped into the backend's key space
/// (i.e. with any `backend_prefix` applied). `Quiet` is always `false` so the
/// backend reports each deletion explicitly, letting the proxy map results back
/// to client keys before applying the client's own quiet preference.
pub fn build_backend_delete_body(backend_keys: &[String]) -> String {
    #[derive(Serialize)]
    #[serde(rename = "Delete")]
    struct Body<'a> {
        #[serde(rename = "Quiet")]
        quiet: bool,
        #[serde(rename = "Object")]
        objects: Vec<Obj<'a>>,
    }
    #[derive(Serialize)]
    struct Obj<'a> {
        #[serde(rename = "Key")]
        key: &'a str,
    }
    let body = Body {
        quiet: false,
        objects: backend_keys.iter().map(|k| Obj { key: k }).collect(),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        quick_xml::se::to_string(&body).unwrap_or_default()
    )
}

/// A per-key error in a `<DeleteResult>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteError {
    /// The object key the error applies to.
    #[serde(rename = "Key")]
    pub key: String,
    /// S3 error code (e.g. `AccessDenied`).
    #[serde(rename = "Code")]
    pub code: String,
    /// Human-readable message.
    #[serde(rename = "Message")]
    pub message: String,
}

/// The backend's keys that were deleted and any per-key errors it reported.
#[derive(Debug)]
pub struct BackendOutcome {
    /// Backend keys reported as deleted.
    pub deleted: Vec<String>,
    /// Per-key errors reported by the backend (backend key space).
    pub errors: Vec<DeleteError>,
}

/// Parse a backend `<DeleteResult>` response.
///
/// Tolerates the extra elements S3 includes (`VersionId`, `DeleteMarker`, …) and
/// returns only what the proxy needs to rebuild the client response.
pub fn parse_backend_result(xml: &[u8]) -> Result<BackendOutcome, ProxyError> {
    #[derive(Deserialize)]
    #[serde(rename = "DeleteResult")]
    struct Result {
        #[serde(default, rename = "Deleted")]
        deleted: Vec<Deleted>,
        #[serde(default, rename = "Error")]
        errors: Vec<DeleteError>,
    }
    #[derive(Deserialize)]
    struct Deleted {
        #[serde(rename = "Key")]
        key: String,
    }
    let parsed: Result = quick_xml::de::from_reader(xml)
        .map_err(|e| ProxyError::BackendError(format!("malformed delete result: {e}")))?;
    Ok(BackendOutcome {
        deleted: parsed.deleted.into_iter().map(|d| d.key).collect(),
        errors: parsed.errors,
    })
}

/// Serialize a client-facing `<DeleteResult>`.
///
/// `deleted` and `errors` are in client key space. In `quiet` mode the
/// `<Deleted>` entries are omitted (S3 semantics); errors are always reported.
pub fn build_delete_result(deleted: &[String], errors: &[DeleteError], quiet: bool) -> String {
    #[derive(Serialize)]
    #[serde(rename = "DeleteResult")]
    struct Result<'a> {
        #[serde(rename = "@xmlns")]
        xmlns: &'static str,
        #[serde(rename = "Deleted")]
        deleted: Vec<Deleted<'a>>,
        #[serde(rename = "Error")]
        errors: &'a [DeleteError],
    }
    #[derive(Serialize)]
    struct Deleted<'a> {
        #[serde(rename = "Key")]
        key: &'a str,
    }
    let deleted = if quiet {
        Vec::new()
    } else {
        deleted.iter().map(|k| Deleted { key: k }).collect()
    };
    let result = Result {
        xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
        deleted,
        errors,
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        quick_xml::se::to_string(&result).unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
        <Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Object><Key>a.txt</Key></Object>
            <Object><Key>nested/b.txt</Key></Object>
        </Delete>"#;

    #[test]
    fn parses_keys_and_quiet_default_false() {
        let req = DeleteRequest::parse(SAMPLE).unwrap();
        assert!(!req.quiet);
        let keys: Vec<_> = req.keys().collect();
        assert_eq!(keys, vec!["a.txt", "nested/b.txt"]);
    }

    #[test]
    fn parses_quiet_flag() {
        let body = br#"<Delete><Quiet>true</Quiet><Object><Key>k</Key></Object></Delete>"#;
        let req = DeleteRequest::parse(body).unwrap();
        assert!(req.quiet);
    }

    #[test]
    fn empty_delete_is_rejected_as_malformed_xml() {
        let body = br#"<Delete></Delete>"#;
        assert!(matches!(
            DeleteRequest::parse(body),
            Err(ProxyError::MalformedXml(_))
        ));
    }

    #[test]
    fn malformed_body_is_rejected_as_malformed_xml() {
        assert!(matches!(
            DeleteRequest::parse(b"not xml"),
            Err(ProxyError::MalformedXml(_))
        ));
    }

    #[test]
    fn over_key_limit_is_rejected() {
        let mut body = String::from("<Delete>");
        for i in 0..=DeleteRequest::MAX_KEYS {
            body.push_str(&format!("<Object><Key>k{i}</Key></Object>"));
        }
        body.push_str("</Delete>");
        assert!(matches!(
            DeleteRequest::parse(body.as_bytes()),
            Err(ProxyError::MalformedXml(_))
        ));
        // Exactly MAX_KEYS is allowed.
        let mut ok = String::from("<Delete>");
        for i in 0..DeleteRequest::MAX_KEYS {
            ok.push_str(&format!("<Object><Key>k{i}</Key></Object>"));
        }
        ok.push_str("</Delete>");
        assert!(DeleteRequest::parse(ok.as_bytes()).is_ok());
    }

    #[test]
    fn backend_body_lists_each_key_non_quiet() {
        let body = build_backend_delete_body(&["p/a.txt".into(), "p/b.txt".into()]);
        assert!(body.contains("<Quiet>false</Quiet>"));
        assert!(body.contains("<Key>p/a.txt</Key>"));
        assert!(body.contains("<Key>p/b.txt</Key>"));
    }

    #[test]
    fn parses_backend_result_with_extra_elements() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
            <DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <Deleted><Key>p/a.txt</Key><DeleteMarker>true</DeleteMarker><VersionId>v1</VersionId></Deleted>
                <Error><Key>p/c.txt</Key><Code>InternalError</Code><Message>oops</Message></Error>
            </DeleteResult>"#;
        let out = parse_backend_result(xml).unwrap();
        assert_eq!(out.deleted, vec!["p/a.txt"]);
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.errors[0].key, "p/c.txt");
        assert_eq!(out.errors[0].code, "InternalError");
    }

    #[test]
    fn build_result_omits_deleted_when_quiet() {
        let deleted = vec!["a.txt".to_string()];
        let errors = vec![DeleteError {
            key: "secret/x".into(),
            code: "AccessDenied".into(),
            message: "denied".into(),
        }];
        let verbose = build_delete_result(&deleted, &errors, false);
        // S3's DeleteResult carries the bucket namespace on the root element.
        assert!(
            verbose.contains("<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">")
        );
        assert!(verbose.contains("<Deleted><Key>a.txt</Key></Deleted>"));
        assert!(verbose.contains("<Key>secret/x</Key>"));
        assert!(verbose.contains("<Code>AccessDenied</Code>"));

        let quiet = build_delete_result(&deleted, &errors, true);
        assert!(!quiet.contains("<Deleted>"));
        // Errors are always reported, even in quiet mode.
        assert!(quiet.contains("<Code>AccessDenied</Code>"));
    }

    #[test]
    fn keys_are_xml_escaped() {
        // A key with XML-significant characters must be escaped in both the
        // backend body and the result.
        let body = build_backend_delete_body(&["a&b<c>.txt".into()]);
        assert!(body.contains("a&amp;b&lt;c&gt;.txt"));
        assert!(!body.contains("a&b<c>.txt"));
    }
}
