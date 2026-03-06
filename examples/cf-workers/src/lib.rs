//! Cloudflare Workers runtime for the S3 proxy gateway.
//!
//! This crate provides implementations of core traits using Cloudflare Workers
//! primitives. Uses zero-copy body forwarding: request and response
//! `ReadableStream`s flow through the JS runtime without touching WASM memory.
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

mod client;
mod fetch_connector;
mod tracing_layer;

use client::{extract_response_headers, FetchHttpExchange, WorkerBackend};
use multistore::config::static_file::{StaticConfig, StaticProvider};
use multistore::proxy::{GatewayResponse, ProxyGateway};
use multistore::route_handler::{ForwardRequest, ProxyResponseBody, ProxyResult, RequestInfo};
use multistore::sealed_token::TokenKey;
use multistore_oidc_provider::backend_auth::MaybeOidcAuth;
use multistore_oidc_provider::jwt::JwtSigner;
use multistore_oidc_provider::route_handler::OidcDiscoveryRouteHandler;
use multistore_oidc_provider::OidcCredentialProvider;
use multistore_sts::route_handler::StsRouteHandler;
use multistore_sts::JwksCache;

use bytes::Bytes;
use http::HeaderMap;
use worker::*;

/// Zero-copy body wrapper. Holds the raw `ReadableStream` from the incoming
/// request, passing it through the Gateway untouched for Forward requests.
struct JsBody(Option<web_sys::ReadableStream>);
// SAFETY: Workers is single-threaded; these are required by Gateway's generic bounds.
unsafe impl Send for JsBody {}
unsafe impl Sync for JsBody {}

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
    tracing::subscriber::set_global_default(tracing_layer::WorkerSubscriber::new()).ok();

    let reqwest_client = reqwest::Client::new();
    let jwks_cache = JwksCache::new(reqwest_client.clone(), std::time::Duration::from_secs(900));
    let token_key = load_token_key(&env)?;

    // Extract body stream BEFORE any wrapping — no lock, zero-cost ref.
    let js_body = JsBody(req.body());

    // Parse request metadata from the raw web_sys::Request.
    let method: http::Method = req.method().parse().unwrap_or(http::Method::GET);
    let url_str = req.url();
    let uri: http::Uri = url_str.parse().unwrap();
    let path = uri.path().to_string();
    let query = uri.query().map(|q| q.to_string());
    let headers = convert_ws_headers(&req.headers());

    // Build OIDC backend auth from env secrets/vars.
    let (oidc_auth, oidc_discovery) = load_oidc_auth(&env)?;

    let config = load_static_config(&env)?;
    let virtual_host_domain = env.var("VIRTUAL_HOST_DOMAIN").ok().map(|v| v.to_string());
    let sts_creds = config.clone();

    // Build the gateway with route handlers
    let mut gateway = ProxyGateway::new(
        WorkerBackend,
        config.clone(),
        config,
        virtual_host_domain,
        token_key.clone(),
    )
    .with_backend_auth(oidc_auth)
    .with_route_handler(StsRouteHandler::new(sts_creds, jwks_cache, token_key));
    if let Some(discovery) = oidc_discovery {
        gateway = gateway.with_route_handler(discovery);
    }

    let req_info = RequestInfo {
        method: &method,
        path: &path,
        query: query.as_deref(),
        headers: &headers,
    };

    Ok(
        match gateway
            .handle_request(&req_info, js_body, collect_js_body)
            .await
        {
            GatewayResponse::Response(result) => proxy_result_to_ws_response(result),
            GatewayResponse::Forward(fwd, body) => forward_to_backend(fwd, body).await,
        },
    )
}

// ── Zero-copy forwarding ────────────────────────────────────────────

/// Execute a Forward request via the Fetch API with zero-copy streaming.
///
/// The original `ReadableStream` from the client request is passed directly
/// to `web_sys::fetch` for PUT uploads — no bytes flow through WASM memory.
/// The backend response's `ReadableStream` is similarly passed through to the
/// client without buffering.
async fn forward_to_backend(fwd: ForwardRequest, body: JsBody) -> web_sys::Response {
    match forward_to_backend_inner(fwd, body).await {
        Ok(resp) => resp,
        Err(msg) => {
            tracing::error!(error = %msg, "forward request failed");
            ws_error_response(502, "Bad Gateway")
        }
    }
}

async fn forward_to_backend_inner(
    fwd: ForwardRequest,
    body: JsBody,
) -> std::result::Result<web_sys::Response, String> {
    // Build web_sys::Headers from the forwarding headers.
    let ws_headers =
        web_sys::Headers::new().map_err(|e| format!("failed to create Headers: {:?}", e))?;
    for (key, value) in fwd.headers.iter() {
        if let Ok(v) = value.to_str() {
            let _ = ws_headers.set(key.as_str(), v);
        }
    }

    // Build web_sys::RequestInit.
    let init = web_sys::RequestInit::new();
    init.set_method(fwd.method.as_str());
    init.set_headers(&ws_headers.into());

    // For PUT: attach the original ReadableStream directly (zero-copy!).
    if fwd.method == http::Method::PUT {
        if let Some(ref stream) = body.0 {
            init.set_body(stream);
        }
    }

    // Build the outgoing request.
    let ws_request = web_sys::Request::new_with_str_and_init(fwd.url.as_str(), &init)
        .map_err(|e| format!("failed to create request: {:?}", e))?;

    // Fetch via the worker crate's Fetch API.
    let worker_req: worker::Request = ws_request.into();
    let worker_resp = worker::Fetch::Request(worker_req)
        .send()
        .await
        .map_err(|e| format!("fetch failed: {}", e))?;

    // Convert to web_sys::Response to access the body stream.
    let backend_ws: web_sys::Response = worker_resp.into();
    let status = backend_ws.status();

    // Build filtered response headers using the existing allowlist.
    let resp_headers = extract_response_headers(&backend_ws.headers());
    let ws_resp_headers = http_headermap_to_ws_headers(&resp_headers)
        .map_err(|e| format!("failed to build response headers: {:?}", e))?;

    // Build response with the backend's body stream (zero-copy!).
    let resp_init = web_sys::ResponseInit::new();
    resp_init.set_status(status);
    resp_init.set_headers(&ws_resp_headers.into());

    web_sys::Response::new_with_opt_readable_stream_and_init(backend_ws.body().as_ref(), &resp_init)
        .map_err(|e| format!("failed to build response: {:?}", e))
}

// ── Body collection (NeedsBody path) ───────────────────────────────

/// Materialize a `JsBody` into `Bytes` for the NeedsBody path.
///
/// Uses the `Response::arrayBuffer()` JS trick: wrap the stream in a
/// `web_sys::Response`, call `.array_buffer()`, and convert via `Uint8Array`.
/// This is only used for small multipart payloads.
async fn collect_js_body(body: JsBody) -> std::result::Result<Bytes, String> {
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

// ── Response builders ───────────────────────────────────────────────

/// Convert a `ProxyResult` (small buffered XML/JSON) to a `web_sys::Response`.
fn proxy_result_to_ws_response(result: ProxyResult) -> web_sys::Response {
    let ws_headers = http_headermap_to_ws_headers(&result.headers)
        .unwrap_or_else(|_| web_sys::Headers::new().unwrap());

    let resp_init = web_sys::ResponseInit::new();
    resp_init.set_status(result.status);
    resp_init.set_headers(&ws_headers.into());

    match result.body {
        ProxyResponseBody::Empty => {
            web_sys::Response::new_with_opt_str_and_init(None, &resp_init).unwrap()
        }
        ProxyResponseBody::Bytes(bytes) => {
            let uint8 = js_sys::Uint8Array::from(bytes.as_ref());
            web_sys::Response::new_with_opt_buffer_source_and_init(Some(&uint8), &resp_init)
                .unwrap()
        }
    }
}

/// Build a plain-text error response.
fn ws_error_response(status: u16, message: &str) -> web_sys::Response {
    let init = web_sys::ResponseInit::new();
    init.set_status(status);
    web_sys::Response::new_with_opt_str_and_init(Some(message), &init)
        .unwrap_or_else(|_| web_sys::Response::new().unwrap())
}

// ── Header conversion helpers ───────────────────────────────────────

/// Convert `web_sys::Headers` to `http::HeaderMap` by iterating all entries.
fn convert_ws_headers(ws_headers: &web_sys::Headers) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for entry in ws_headers.entries() {
        let Ok(pair) = entry else { continue };
        let arr: js_sys::Array = pair.into();
        let Some(key) = arr.get(0).as_string() else {
            continue;
        };
        let Some(value) = arr.get(1).as_string() else {
            continue;
        };
        let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes()) else {
            continue;
        };
        let Ok(val) = http::header::HeaderValue::from_str(&value) else {
            continue;
        };
        headers.append(name, val);
    }
    headers
}

/// Convert `http::HeaderMap` to `web_sys::Headers`.
fn http_headermap_to_ws_headers(
    headers: &HeaderMap,
) -> std::result::Result<web_sys::Headers, wasm_bindgen::JsValue> {
    let ws = web_sys::Headers::new()?;
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            ws.set(key.as_str(), v)?;
        }
    }
    Ok(ws)
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

fn load_static_config(env: &Env) -> Result<StaticProvider> {
    load_config_from_env(env, "PROXY_CONFIG")
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

type OidcAuth = MaybeOidcAuth<FetchHttpExchange>;

/// Load OIDC provider config from env secrets/vars.
///
/// Returns `MaybeOidcAuth::Enabled` if both `OIDC_PROVIDER_KEY` (secret) and
/// `OIDC_PROVIDER_ISSUER` (var) are set; otherwise `Disabled`.
fn load_oidc_auth(env: &Env) -> Result<(OidcAuth, Option<OidcDiscoveryRouteHandler>)> {
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
            let discovery = OidcDiscoveryRouteHandler::new(issuer, signer);
            Ok((auth, Some(discovery)))
        }
        _ => Ok((MaybeOidcAuth::Disabled, None)),
    }
}
