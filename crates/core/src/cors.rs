//! CORS (Cross-Origin Resource Sharing) middleware.
//!
//! Provides per-bucket CORS configuration and a middleware that handles
//! preflight (`OPTIONS`) requests and stamps CORS headers on normal
//! responses. The middleware sits *before* auth so that preflight requests
//! succeed without credentials.
//!
//! ## Setup
//!
//! 1. Implement [`CorsProvider`] for your config backend (or use the
//!    built-in `StaticProvider` implementation).
//! 2. Register [`CorsMiddleware`] on the gateway **before** the S3
//!    defaults so preflight requests are handled without authentication.
//!
//! ```rust,ignore
//! let gateway = ProxyGateway::new(backend, forwarder, domain.clone())
//!     .with_middleware(CorsMiddleware::new(config.clone(), domain))
//!     .with_s3_defaults(config.clone(), config);
//! ```

use std::future::Future;

use http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::error::ProxyError;
use crate::maybe_send::{MaybeSend, MaybeSync};
use crate::middleware::{Middleware, Next, RequestContext};
use crate::route_handler::{HandlerAction, ProxyResponseBody, ProxyResult};

// ---------------------------------------------------------------------------
// CorsConfig
// ---------------------------------------------------------------------------

/// Per-bucket CORS configuration.
///
/// Controls which origins, methods, and headers are permitted for
/// cross-origin requests targeting a particular virtual bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Origins allowed to make cross-origin requests.
    /// Use `"*"` to allow any origin.
    pub allowed_origins: Vec<String>,

    /// HTTP methods allowed in cross-origin requests.
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,

    /// Request headers allowed in cross-origin requests.
    #[serde(default)]
    pub allowed_headers: Vec<String>,

    /// Response headers exposed to the browser.
    #[serde(default)]
    pub expose_headers: Vec<String>,

    /// How long (in seconds) the browser may cache preflight results.
    #[serde(default = "default_max_age")]
    pub max_age_seconds: u32,

    /// Whether the response may be shared when the request's credentials
    /// mode is `include`.
    #[serde(default)]
    pub allow_credentials: bool,
}

fn default_allowed_methods() -> Vec<String> {
    vec!["GET".into(), "HEAD".into()]
}

fn default_max_age() -> u32 {
    3600
}

// ---------------------------------------------------------------------------
// CorsProvider trait
// ---------------------------------------------------------------------------

/// Trait for looking up per-bucket CORS configuration.
///
/// Implementors return `Some(CorsConfig)` for buckets that should emit
/// CORS headers, or `None` to skip CORS entirely.
pub trait CorsProvider: MaybeSend + MaybeSync + 'static {
    /// Return the CORS configuration for the given bucket, if any.
    fn get_cors_config(
        &self,
        bucket_name: &str,
    ) -> impl Future<Output = Option<CorsConfig>> + MaybeSend;
}

// ---------------------------------------------------------------------------
// CorsMiddleware
// ---------------------------------------------------------------------------

/// Middleware that handles CORS preflight and stamps CORS headers.
///
/// Place this middleware **before** auth middleware so that `OPTIONS`
/// preflight requests succeed without credentials.
pub struct CorsMiddleware<P> {
    provider: P,
    virtual_host_domain: Option<String>,
}

impl<P> CorsMiddleware<P> {
    /// Create a new CORS middleware.
    ///
    /// `virtual_host_domain` is needed to extract bucket names from
    /// virtual-hosted-style requests (e.g., `bucket.s3.example.com`).
    pub fn new(provider: P, virtual_host_domain: Option<String>) -> Self {
        Self {
            provider,
            virtual_host_domain,
        }
    }
}

impl<P: CorsProvider> Middleware for CorsMiddleware<P> {
    async fn handle<'a>(
        &'a self,
        ctx: RequestContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        // Extract Origin header; if absent, CORS does not apply.
        let origin = match ctx
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
        {
            Some(o) => o,
            None => return next.run(ctx).await,
        };

        // Extract bucket name from the request.
        let bucket_name =
            match extract_bucket_name(ctx.path, ctx.headers, self.virtual_host_domain.as_deref()) {
                Some(b) => b,
                None => return next.run(ctx).await,
            };

        // Look up CORS config for this bucket.
        let config = match self.provider.get_cors_config(&bucket_name).await {
            Some(c) => c,
            None => return next.run(ctx).await,
        };

        // Validate origin.
        if !origin_allowed(&config, &origin) {
            return next.run(ctx).await;
        }

        // Handle preflight (OPTIONS).
        if *ctx.method == http::Method::OPTIONS {
            if let Some(result) = build_preflight_response(&config, &origin, ctx.headers) {
                return Ok(HandlerAction::Response(result));
            }
            // Not a valid preflight (missing required headers); fall through.
            return next.run(ctx).await;
        }

        // Non-preflight: continue chain, then stamp CORS headers.
        let mut action = next.run(ctx).await?;
        inject_cors_headers(action.response_headers_mut(), &config, &origin);
        Ok(action)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Check whether `origin` is allowed by the given CORS configuration.
pub fn origin_allowed(config: &CorsConfig, origin: &str) -> bool {
    config
        .allowed_origins
        .iter()
        .any(|o| o == "*" || o == origin)
}

/// Build a 204 preflight response if the request carries the required
/// CORS preflight headers. Returns `None` if the request is not a valid
/// preflight (missing `Access-Control-Request-Method`).
pub fn build_preflight_response(
    config: &CorsConfig,
    origin: &str,
    request_headers: &HeaderMap,
) -> Option<ProxyResult> {
    // A valid preflight must include Access-Control-Request-Method.
    let request_method = request_headers
        .get("access-control-request-method")
        .and_then(|v| v.to_str().ok())?;

    // Check if the requested method is allowed.
    let method_allowed = config
        .allowed_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(request_method));
    if !method_allowed {
        return None;
    }

    let mut headers = HeaderMap::new();

    // Origin
    if config.allowed_origins.iter().any(|o| o == "*") && !config.allow_credentials {
        headers.insert("access-control-allow-origin", "*".parse().unwrap());
    } else {
        headers.insert(
            "access-control-allow-origin",
            origin.parse().unwrap_or_else(|_| "*".parse().unwrap()),
        );
        headers.insert("vary", "Origin".parse().unwrap());
    }

    // Methods
    headers.insert(
        "access-control-allow-methods",
        config.allowed_methods.join(", ").parse().unwrap(),
    );

    // Allowed headers
    if !config.allowed_headers.is_empty() {
        headers.insert(
            "access-control-allow-headers",
            config.allowed_headers.join(", ").parse().unwrap(),
        );
    } else if let Some(req_headers) = request_headers
        .get("access-control-request-headers")
        .and_then(|v| v.to_str().ok())
    {
        // Mirror the requested headers when no explicit list is configured.
        headers.insert("access-control-allow-headers", req_headers.parse().unwrap());
    }

    // Max age
    headers.insert(
        "access-control-max-age",
        config.max_age_seconds.to_string().parse().unwrap(),
    );

    // Credentials
    if config.allow_credentials {
        headers.insert("access-control-allow-credentials", "true".parse().unwrap());
    }

    Some(ProxyResult {
        status: 204,
        headers,
        body: ProxyResponseBody::Empty,
    })
}

/// Inject CORS headers into a response header map for a non-preflight
/// request.
pub fn inject_cors_headers(headers: &mut HeaderMap, config: &CorsConfig, origin: &str) {
    // Origin
    if config.allowed_origins.iter().any(|o| o == "*") && !config.allow_credentials {
        headers.insert("access-control-allow-origin", "*".parse().unwrap());
    } else {
        headers.insert(
            "access-control-allow-origin",
            origin.parse().unwrap_or_else(|_| "*".parse().unwrap()),
        );
        // Vary: Origin is required when the value is not `*`.
        headers.append("vary", "Origin".parse().unwrap());
    }

    // Expose headers
    if !config.expose_headers.is_empty() {
        headers.insert(
            "access-control-expose-headers",
            config.expose_headers.join(", ").parse().unwrap(),
        );
    }

    // Credentials
    if config.allow_credentials {
        headers.insert("access-control-allow-credentials", "true".parse().unwrap());
    }
}

/// Extract the bucket name from the request path or Host header.
///
/// Checks virtual-hosted-style first (if `virtual_host_domain` is set),
/// then falls back to path-style (`/{bucket}/...`).
pub fn extract_bucket_name(
    path: &str,
    headers: &HeaderMap,
    virtual_host_domain: Option<&str>,
) -> Option<String> {
    // Virtual-hosted style: Host = {bucket}.{domain}
    if let Some(domain) = virtual_host_domain {
        if let Some(host) = headers.get("host").and_then(|v| v.to_str().ok()) {
            let host = host.split(':').next().unwrap_or(host);
            if let Some(bucket) = host.strip_suffix(&format!(".{}", domain)) {
                if !bucket.is_empty() {
                    return Some(bucket.to_string());
                }
            }
        }
    }

    // Path-style: /{bucket}/...
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let bucket = trimmed.split('/').next()?;
    if bucket.is_empty() {
        return None;
    }
    Some(bucket.to_string())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CorsConfig {
        CorsConfig {
            allowed_origins: vec!["https://example.com".into()],
            allowed_methods: vec!["GET".into(), "HEAD".into()],
            allowed_headers: vec![],
            expose_headers: vec![],
            max_age_seconds: 3600,
            allow_credentials: false,
        }
    }

    // -- origin_allowed ------------------------------------------------------

    #[test]
    fn origin_allowed_exact_match() {
        let config = test_config();
        assert!(origin_allowed(&config, "https://example.com"));
    }

    #[test]
    fn origin_allowed_no_match() {
        let config = test_config();
        assert!(!origin_allowed(&config, "https://evil.com"));
    }

    #[test]
    fn origin_allowed_wildcard() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            ..test_config()
        };
        assert!(origin_allowed(&config, "https://anything.example.org"));
    }

    // -- build_preflight_response -------------------------------------------

    #[test]
    fn preflight_valid() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("access-control-request-method", "GET".parse().unwrap());

        let resp = build_preflight_response(&config, "https://example.com", &headers);
        assert!(resp.is_some());
        let resp = resp.unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(
            resp.headers
                .get("access-control-allow-origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn preflight_missing_request_method() {
        let config = test_config();
        let headers = HeaderMap::new();
        let resp = build_preflight_response(&config, "https://example.com", &headers);
        assert!(resp.is_none());
    }

    #[test]
    fn preflight_disallowed_method() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("access-control-request-method", "DELETE".parse().unwrap());

        let resp = build_preflight_response(&config, "https://example.com", &headers);
        assert!(resp.is_none());
    }

    #[test]
    fn preflight_wildcard_origin_no_credentials() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            ..test_config()
        };
        let mut headers = HeaderMap::new();
        headers.insert("access-control-request-method", "GET".parse().unwrap());

        let resp = build_preflight_response(&config, "https://example.com", &headers).unwrap();
        assert_eq!(
            resp.headers
                .get("access-control-allow-origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );
        assert!(resp.headers.get("vary").is_none());
    }

    #[test]
    fn preflight_specific_origin_has_vary() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert("access-control-request-method", "GET".parse().unwrap());

        let resp = build_preflight_response(&config, "https://example.com", &headers).unwrap();
        assert_eq!(
            resp.headers.get("vary").unwrap().to_str().unwrap(),
            "Origin"
        );
    }

    #[test]
    fn preflight_with_credentials() {
        let config = CorsConfig {
            allow_credentials: true,
            ..test_config()
        };
        let mut headers = HeaderMap::new();
        headers.insert("access-control-request-method", "GET".parse().unwrap());

        let resp = build_preflight_response(&config, "https://example.com", &headers).unwrap();
        assert_eq!(
            resp.headers
                .get("access-control-allow-credentials")
                .unwrap()
                .to_str()
                .unwrap(),
            "true"
        );
        // With credentials, even wildcard origins should echo back the origin.
    }

    // -- inject_cors_headers ------------------------------------------------

    #[test]
    fn inject_headers_wildcard() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            ..test_config()
        };
        let mut headers = HeaderMap::new();
        inject_cors_headers(&mut headers, &config, "https://example.com");
        assert_eq!(
            headers
                .get("access-control-allow-origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );
    }

    #[test]
    fn inject_headers_specific_origin() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        inject_cors_headers(&mut headers, &config, "https://example.com");
        assert_eq!(
            headers
                .get("access-control-allow-origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "https://example.com"
        );
        assert_eq!(headers.get("vary").unwrap().to_str().unwrap(), "Origin");
    }

    #[test]
    fn inject_headers_with_credentials() {
        let config = CorsConfig {
            allow_credentials: true,
            ..test_config()
        };
        let mut headers = HeaderMap::new();
        inject_cors_headers(&mut headers, &config, "https://example.com");
        assert_eq!(
            headers
                .get("access-control-allow-credentials")
                .unwrap()
                .to_str()
                .unwrap(),
            "true"
        );
    }

    #[test]
    fn inject_headers_expose_headers() {
        let config = CorsConfig {
            expose_headers: vec!["x-custom".into(), "etag".into()],
            ..test_config()
        };
        let mut headers = HeaderMap::new();
        inject_cors_headers(&mut headers, &config, "https://example.com");
        assert_eq!(
            headers
                .get("access-control-expose-headers")
                .unwrap()
                .to_str()
                .unwrap(),
            "x-custom, etag"
        );
    }

    // -- extract_bucket_name ------------------------------------------------

    #[test]
    fn extract_bucket_path_style() {
        let headers = HeaderMap::new();
        assert_eq!(
            extract_bucket_name("/my-bucket/key.txt", &headers, None),
            Some("my-bucket".into())
        );
    }

    #[test]
    fn extract_bucket_path_style_no_key() {
        let headers = HeaderMap::new();
        assert_eq!(
            extract_bucket_name("/my-bucket/", &headers, None),
            Some("my-bucket".into())
        );
    }

    #[test]
    fn extract_bucket_virtual_hosted() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "my-bucket.s3.example.com".parse().unwrap());
        assert_eq!(
            extract_bucket_name("/key.txt", &headers, Some("s3.example.com")),
            Some("my-bucket".into())
        );
    }

    #[test]
    fn extract_bucket_root_path() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bucket_name("/", &headers, None), None);
    }

    #[test]
    fn extract_bucket_empty_path() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bucket_name("", &headers, None), None);
    }

    #[test]
    fn extract_bucket_virtual_hosted_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "my-bucket.s3.example.com:8080".parse().unwrap());
        assert_eq!(
            extract_bucket_name("/key.txt", &headers, Some("s3.example.com")),
            Some("my-bucket".into())
        );
    }
}
