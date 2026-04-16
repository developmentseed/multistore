//! CORS header utilities for browser-accessible S3 proxies.

use http::HeaderMap;

/// Set permissive CORS headers suitable for public, browser-accessible
/// S3-compatible read-only proxies.
///
/// Sets:
/// - `access-control-allow-origin: *`
/// - `access-control-allow-methods: GET, HEAD, OPTIONS`
/// - `access-control-allow-headers: *`
/// - `access-control-expose-headers: *`
///
/// Existing CORS headers in the map are overwritten.
pub fn add_cors_headers(headers: &mut HeaderMap) {
    let pairs = [
        ("access-control-allow-origin", "*"),
        ("access-control-allow-methods", "GET, HEAD, OPTIONS"),
        ("access-control-allow-headers", "*"),
        ("access-control-expose-headers", "*"),
    ];
    for (name, value) in pairs {
        if let Ok(v) = value.parse() {
            headers.insert(name, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_all_four_cors_headers() {
        let mut h = HeaderMap::new();
        add_cors_headers(&mut h);
        assert_eq!(h.get("access-control-allow-origin").unwrap(), "*");
        assert_eq!(
            h.get("access-control-allow-methods").unwrap(),
            "GET, HEAD, OPTIONS"
        );
        assert_eq!(h.get("access-control-allow-headers").unwrap(), "*");
        assert_eq!(h.get("access-control-expose-headers").unwrap(), "*");
    }

    #[test]
    fn overwrites_existing() {
        let mut h = HeaderMap::new();
        h.insert(
            "access-control-allow-origin",
            "https://example.com".parse().unwrap(),
        );
        add_cors_headers(&mut h);
        assert_eq!(h.get("access-control-allow-origin").unwrap(), "*");
    }
}
