//! Newtype wrapper for `web_sys::Headers` enabling ergonomic conversions
//! with [`http::HeaderMap`].
//!
//! Rust's orphan rule prevents implementing `From<&HeaderMap>` directly on
//! `web_sys::Headers`. This wrapper provides those conversions while
//! remaining transparent to use via [`into_inner`](WsHeaders::into_inner).

use http::HeaderMap;

/// Thin wrapper around [`web_sys::Headers`] that enables [`From`] conversions
/// with [`HeaderMap`].
///
/// # Example
///
/// ```rust,ignore
/// let ws: WsHeaders = WsHeaders::from(&header_map);
/// init.set_headers(&ws.into_inner().into());
/// ```
pub struct WsHeaders(web_sys::Headers);

impl WsHeaders {
    /// Unwrap into the inner `web_sys::Headers`.
    pub fn into_inner(self) -> web_sys::Headers {
        self.0
    }
}

impl From<&HeaderMap> for WsHeaders {
    fn from(headers: &HeaderMap) -> Self {
        let ws = web_sys::Headers::new().unwrap();
        for (key, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                let _ = ws.set(key.as_str(), v);
            }
        }
        WsHeaders(ws)
    }
}
