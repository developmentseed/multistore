//! Detection of AWS SigV4 streaming ("aws-chunked") uploads.
//!
//! Modern AWS clients (aws-cli ≥ 2.23, recent SDKs) send `PutObject`/`UploadPart`
//! bodies as `Content-Encoding: aws-chunked` framing with an
//! `x-amz-content-sha256: STREAMING-…` sentinel rather than a plain payload. S3
//! only de-chunks that framing for a request signed with the matching streaming
//! sentinel, so the proxy must re-sign the request seed (not presign) and stream
//! the framing through untouched — see `ProxyGateway::build_streaming_forward`.

use http::HeaderMap;

/// How a streaming ("aws-chunked") upload's chunks are authenticated — which
/// decides whether the proxy can forward the framing after re-signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamingUpload {
    /// `STREAMING-UNSIGNED-PAYLOAD[-TRAILER]` — chunks are framed but not
    /// individually signed. The proxy can re-sign the request seed with the
    /// backend credentials and stream the framing through for S3 to de-chunk.
    Unsigned,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]` — each chunk carries a
    /// signature chained from the client's signing key, which cannot survive the
    /// proxy re-signing the request to the backend with different credentials.
    /// The proxy cannot forward these.
    Signed,
}

/// Classify a request body from its `x-amz-content-sha256`, returning `None`
/// for an ordinary (non-streaming) upload.
pub(crate) fn streaming_upload(headers: &HeaderMap) -> Option<StreamingUpload> {
    let variant = headers
        .get("x-amz-content-sha256")?
        .to_str()
        .ok()?
        .strip_prefix("STREAMING-")?;
    Some(if variant.contains("UNSIGNED") {
        StreamingUpload::Unsigned
    } else {
        StreamingUpload::Signed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(content_sha256: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        if !content_sha256.is_empty() {
            h.insert("x-amz-content-sha256", content_sha256.parse().unwrap());
        }
        h
    }

    #[test]
    fn unsigned_streaming_is_unsigned() {
        // The aws-cli/SDK default (CRC64NVME trailer), and the no-trailer form.
        assert_eq!(
            streaming_upload(&headers("STREAMING-UNSIGNED-PAYLOAD-TRAILER")),
            Some(StreamingUpload::Unsigned)
        );
        assert_eq!(
            streaming_upload(&headers("STREAMING-UNSIGNED-PAYLOAD")),
            Some(StreamingUpload::Unsigned)
        );
    }

    #[test]
    fn signed_streaming_is_signed() {
        assert_eq!(
            streaming_upload(&headers("STREAMING-AWS4-HMAC-SHA256-PAYLOAD")),
            Some(StreamingUpload::Signed)
        );
        assert_eq!(
            streaming_upload(&headers("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")),
            Some(StreamingUpload::Signed)
        );
    }

    #[test]
    fn non_streaming_is_none() {
        assert_eq!(streaming_upload(&headers("UNSIGNED-PAYLOAD")), None);
        assert_eq!(
            streaming_upload(&headers(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )),
            None
        );
        assert_eq!(streaming_upload(&headers("")), None);
    }
}
