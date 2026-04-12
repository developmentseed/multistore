//! Zero-copy body wrapper for Cloudflare Workers.
//!
//! Holds the raw `ReadableStream` from an incoming request so it can be
//! forwarded to the backend without copying through WASM memory.

use bytes::Bytes;

/// Zero-copy body wrapper. Holds the raw `ReadableStream` from the incoming
/// request, passing it through the Gateway untouched for Forward requests.
pub struct JsBody(Option<web_sys::ReadableStream>);

impl JsBody {
    /// Wrap an optional `ReadableStream` from a `web_sys::Request`.
    pub fn new(stream: Option<web_sys::ReadableStream>) -> Self {
        Self(stream)
    }

    /// Borrow the inner stream, if present.
    pub fn stream(&self) -> Option<&web_sys::ReadableStream> {
        self.0.as_ref()
    }
}

// SAFETY: Workers is single-threaded; these are required by Gateway's generic bounds.
unsafe impl Send for JsBody {}
unsafe impl Sync for JsBody {}

/// Materialize a `JsBody` into `Bytes` for the NeedsBody path.
///
/// Uses the `Response::arrayBuffer()` JS trick: wrap the stream in a
/// `web_sys::Response`, call `.array_buffer()`, and convert via `Uint8Array`.
/// This is only used for small multipart payloads.
pub async fn collect_js_body(body: JsBody) -> std::result::Result<Bytes, String> {
    match body.0 {
        None => Ok(Bytes::new()),
        Some(stream) => {
            let resp = web_sys::Response::new_with_opt_readable_stream(Some(&stream))
                .map_err(|e| format!("Response::new failed: {:?}", e))?;
            let promise = resp
                .array_buffer()
                .map_err(|e| format!("arrayBuffer() failed: {:?}", e))?;
            let buf = wasm_bindgen_futures::JsFuture::from(promise)
                .await
                .map_err(|e| format!("arrayBuffer await failed: {:?}", e))?;
            let uint8 = js_sys::Uint8Array::new(&buf);
            Ok(Bytes::from(uint8.to_vec()))
        }
    }
}
