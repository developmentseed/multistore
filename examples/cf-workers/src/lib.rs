//! Cloudflare Workers runtime for the S3 proxy gateway.
//!
//! This crate provides an example deployment using the `multistore-cf-workers` crate
//! for runtime primitives and static config for bucket/credential registries.
//!
//! # Architecture
//!
//! ```text
//! Client -> Worker (web_sys::Request — body stream NOT locked)
//!   -> resolve request (ProxyGateway with static config registries)
//!   -> Forward: web_sys::fetch with ReadableStream passthrough (zero-copy)
//!   -> Response: LIST XML via object_store, errors, synthetic responses
//!   -> NeedsBody: multipart operations via raw signed HTTP
//! ```
//!
//! # Configuration
//!
//! On Workers, configuration is loaded from:
//! - Environment variables / secrets for simple setups
//! - Workers KV for dynamic configuration

mod bandwidth;
mod metering;
mod rate_limit;

pub use bandwidth::BandwidthMeter;

use multistore::proxy::ProxyGateway;
use multistore::router::Router;
use multistore_cf_workers::{
    collect_js_body, headermap_from_js, response_from_gateway, JsBody, WorkerBackend,
    WorkerSubscriber,
};
use multistore_oidc_provider::backend_auth::MaybeOidcAuth;
use multistore_oidc_provider::jwt::JwtSigner;
use multistore_oidc_provider::route_handler::OidcRouterExt;
use multistore_oidc_provider::{HttpExchange, OidcCredentialProvider, OidcProviderError};
use multistore_static_config::{StaticConfig, StaticProvider};
use multistore_sts::route_handler::StsRouterExt;
use multistore_sts::JwksCache;
use multistore_sts::TokenKey;
use rate_limit::CfRateLimiter;

use worker::*;

/// The Worker entry point.
///
/// Accepts `web_sys::Request` directly (via the worker crate's `FromRequest`
/// trait) so the body `ReadableStream` is never locked by `worker::Body::new()`.
/// Returns `web_sys::Response` directly, bypassing the `axum::Body` → `to_wasm()`
/// copy path.
///
/// Wrangler config (`wrangler.toml`) should bind:
/// - `PROXY_CONFIG` environment variable for configuration
/// - `VIRTUAL_HOST_DOMAIN` environment variable (optional)
#[event(fetch)]
async fn fetch(req: web_sys::Request, env: Env, _ctx: Context) -> Result<web_sys::Response> {
    // Initialize panic hook for better error messages
    console_error_panic_hook::set_once();

    // Initialize tracing subscriber (idempotent — ignored if already set)
    tracing::subscriber::set_global_default(WorkerSubscriber::new()).ok();

    let reqwest_client = reqwest::Client::new();
    let jwks_cache = JwksCache::new(reqwest_client.clone(), std::time::Duration::from_secs(900));
    let token_key = load_token_key(&env)?;

    // Build OIDC backend auth from env secrets/vars.
    let (oidc_auth, oidc_signer, oidc_issuer) = load_oidc_auth(&env)?;

    let config = load_config_from_env(&env, "PROXY_CONFIG")?;
    let virtual_host_domain = env.var("VIRTUAL_HOST_DOMAIN").ok().map(|v| v.to_string());
    let sts_creds = config.clone();

    // Build router with OIDC discovery (if configured) and STS.
    let mut router = Router::new();
    if let (Some(signer), Some(issuer)) = (oidc_signer, oidc_issuer) {
        router = router.with_oidc_discovery(issuer, signer);
    }
    router = router.with_sts(sts_creds, jwks_cache, token_key.clone());

    // Build the gateway with the router.
    let mut gateway = ProxyGateway::new(WorkerBackend, config.clone(), config, virtual_host_domain)
        .with_middleware(oidc_auth)
        .with_router(router);

    if let Some(rate_limiter) = load_rate_limiter(&env) {
        gateway = gateway.with_middleware(rate_limiter);
    }
    if let Some(bandwidth) = load_bandwidth_meter(&env) {
        gateway = gateway.with_middleware(bandwidth);
    }
    if let Some(ref resolver) = token_key {
        gateway = gateway.with_credential_resolver(resolver.clone());
    }

    // Extract body stream BEFORE any wrapping — no lock, zero-cost ref.
    let js_body = JsBody(req.body());

    // Parse request metadata from the raw web_sys::Request.
    let method: http::Method = req.method().parse().unwrap_or(http::Method::GET);
    let url_str = req.url();
    let uri: http::Uri = url_str.parse().unwrap();
    let path = uri.path().to_string();
    let query = uri.query().map(|q| q.to_string());
    let headers = headermap_from_js(&req.headers());

    let req_info = multistore::route_handler::RequestInfo::new(
        &method,
        &path,
        query.as_deref(),
        &headers,
        None,
    );

    let result = gateway
        .handle_request(&req_info, js_body, collect_js_body)
        .await;
    Ok(response_from_gateway(result))
}

// ── OIDC HTTP exchange ─────────────────────────────────────────────

/// [`HttpExchange`] implementation using reqwest on WASM (wraps `web_sys::fetch`).
#[derive(Clone)]
pub struct FetchHttpExchange;

impl HttpExchange for FetchHttpExchange {
    async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<String, OidcProviderError> {
        let client = reqwest::Client::new();
        let resp = client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(|e| OidcProviderError::HttpError(e.to_string()))?;

        resp.text()
            .await
            .map_err(|e| OidcProviderError::HttpError(e.to_string()))
    }
}

// ── Shared helpers ──────────────────────────────────────────────────

/// Load a StaticProvider from a named env var (supports both JSON string and JS object).
fn load_config_from_env(env: &Env, var_name: &str) -> Result<StaticProvider> {
    if let Ok(var) = env.var(var_name) {
        let config_str = var.to_string();
        tracing::debug!(
            var = var_name,
            config_len = config_str.len(),
            "loaded config as string"
        );
        StaticProvider::from_json(&config_str)
            .map_err(|e| worker::Error::RustError(format!("{} config error: {}", var_name, e)))
    } else {
        tracing::debug!(var = var_name, "loading config as object");
        let static_config: StaticConfig = env
            .object_var(var_name)
            .map_err(|e| worker::Error::RustError(format!("{} config error: {}", var_name, e)))?;
        StaticProvider::from_config(static_config)
            .map_err(|e| worker::Error::RustError(format!("{} config error: {}", var_name, e)))
    }
}

/// Load the optional session token encryption key from the `SESSION_TOKEN_KEY` secret.
fn load_token_key(env: &Env) -> Result<Option<TokenKey>> {
    match env.secret("SESSION_TOKEN_KEY") {
        Ok(val) => {
            let key = TokenKey::from_base64(&val.to_string())
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
            Ok(Some(key))
        }
        Err(_) => Ok(None),
    }
}

/// Load rate limiter middleware from env bindings.
///
/// Returns `Some(CfRateLimiter)` if both `ANON_RATE_LIMITER` and
/// `AUTH_RATE_LIMITER` bindings are configured; otherwise `None`.
fn load_rate_limiter(env: &Env) -> Option<CfRateLimiter> {
    let anon = env.rate_limiter("ANON_RATE_LIMITER").ok()?;
    let auth = env.rate_limiter("AUTH_RATE_LIMITER").ok()?;
    Some(CfRateLimiter::new(anon, auth))
}

/// Load bandwidth metering middleware from env bindings.
///
/// Returns `Some(MeteringMiddleware)` if both `BANDWIDTH_METER` (DO namespace)
/// and `BANDWIDTH_QUOTAS` (quota config) are configured; otherwise `None`.
fn load_bandwidth_meter(
    env: &Env,
) -> Option<
    multistore_metering::MeteringMiddleware<metering::DoBandwidthMeter, metering::DoBandwidthMeter>,
> {
    // Try loading quotas as a JSON string first, then as a TOML object.
    let quotas: std::collections::HashMap<String, metering::BucketQuota> =
        if let Ok(var) = env.var("BANDWIDTH_QUOTAS") {
            serde_json::from_str(&var.to_string())
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to parse BANDWIDTH_QUOTAS as JSON string");
                    e
                })
                .ok()?
        } else {
            env.object_var("BANDWIDTH_QUOTAS")
                .map_err(|e| {
                    tracing::error!(error = %e, "failed to load BANDWIDTH_QUOTAS");
                    e
                })
                .ok()?
        };

    // Two separate namespace bindings because MeteringMiddleware needs two separate instances
    // (one for quota checking, one for recording). DoBandwidthMeter is stateless locally —
    // all state lives in the DO.
    let ns_check = env.durable_object("BANDWIDTH_METER").ok()?;
    let ns_record = env.durable_object("BANDWIDTH_METER").ok()?;

    let checker = metering::DoBandwidthMeter::new(ns_check, quotas.clone());
    let recorder = metering::DoBandwidthMeter::new(ns_record, quotas);

    Some(multistore_metering::MeteringMiddleware::new(
        checker, recorder,
    ))
}

/// Load OIDC provider config from env secrets/vars.
///
/// Returns `MaybeOidcAuth::Enabled` if both `OIDC_PROVIDER_KEY` (secret) and
/// `OIDC_PROVIDER_ISSUER` (var) are set; otherwise `Disabled`. Also returns
/// the signer and issuer for router registration.
fn load_oidc_auth(
    env: &Env,
) -> Result<(
    MaybeOidcAuth<FetchHttpExchange>,
    Option<JwtSigner>,
    Option<String>,
)> {
    let key_pem = match env.secret("OIDC_PROVIDER_KEY") {
        Ok(val) => Some(val.to_string()),
        Err(_) => None,
    };
    let issuer = env.var("OIDC_PROVIDER_ISSUER").ok().map(|v| v.to_string());

    match (key_pem, issuer) {
        (Some(pem), Some(issuer)) => {
            let signer = JwtSigner::from_pem(&pem, "proxy-key-1".into(), 300)
                .map_err(|e| worker::Error::RustError(format!("OIDC signer error: {e}")))?;
            let http = FetchHttpExchange;
            let provider = OidcCredentialProvider::new(
                signer.clone(),
                http,
                issuer.clone(),
                "sts.amazonaws.com".into(),
            );
            let auth = MaybeOidcAuth::Enabled(Box::new(
                multistore_oidc_provider::backend_auth::AwsBackendAuth::new(provider),
            ));
            Ok((auth, Some(signer), Some(issuer)))
        }
        _ => Ok((MaybeOidcAuth::Disabled, None, None)),
    }
}
