//! Cloudflare Workers runtime for the S3 proxy gateway.
//!
//! Uses s3s for S3 protocol handling with `MultistoreService`.
//!
//! # Configuration
//!
//! On Workers, configuration is loaded from:
//! - Environment variables / secrets for simple setups
//! - Workers KV for dynamic configuration

mod bandwidth;
mod client;
mod fetch_connector;
mod metering;
mod rate_limit;
mod tracing_layer;

pub use bandwidth::BandwidthMeter;

use client::WorkerBackend;
use multistore::service::{MultistoreAuth, MultistoreService};
use multistore_static_config::{StaticConfig, StaticProvider};
use s3s::service::S3ServiceBuilder;

use bytes::Bytes;
use http::HeaderMap;
use worker::*;

/// The Worker entry point.
#[event(fetch)]
async fn fetch(req: web_sys::Request, env: Env, _ctx: Context) -> Result<web_sys::Response> {
    // Initialize panic hook for better error messages
    console_error_panic_hook::set_once();

    // Initialize tracing subscriber (idempotent — ignored if already set)
    tracing::subscriber::set_global_default(tracing_layer::WorkerSubscriber::new()).ok();

    let config = load_config_from_env(&env, "PROXY_CONFIG")?;
    let virtual_host_domain = env.var("VIRTUAL_HOST_DOMAIN").ok().map(|v| v.to_string());

    // Build the s3s service
    let service = MultistoreService::new(config.clone(), WorkerBackend);
    let auth = MultistoreAuth::new(config);

    let mut builder = S3ServiceBuilder::new(service);
    builder.set_auth(auth);

    if let Some(ref domain) = virtual_host_domain {
        builder.set_host(
            s3s::host::SingleDomain::new(domain).map_err(|e| {
                worker::Error::RustError(format!("invalid virtual host domain: {e}"))
            })?,
        );
    }

    let s3_service = builder.build();

    // Convert web_sys::Request → http::Request<s3s::Body>
    let method: http::Method = req.method().parse().unwrap_or(http::Method::GET);
    let url_str = req.url();
    let uri: http::Uri = url_str
        .parse()
        .map_err(|e| worker::Error::RustError(format!("invalid URI: {e}")))?;
    let headers = convert_ws_headers(&req.headers());

    // Collect body to bytes
    let body_bytes = collect_ws_body(&req).await?;
    let s3_body = s3s::Body::from(body_bytes);

    // Build the http::Request
    let mut http_req = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(s3_body)
        .map_err(|e| worker::Error::RustError(format!("failed to build request: {e}")))?;
    *http_req.headers_mut() = headers;

    // Call the s3s service
    let s3_resp = s3_service
        .call(http_req)
        .await
        .map_err(|e| worker::Error::RustError(format!("s3s error: {e:?}")))?;

    // Convert http::Response<s3s::Body> → web_sys::Response
    s3_response_to_ws(s3_resp)
}

/// Collect body from web_sys::Request into Bytes.
async fn collect_ws_body(req: &web_sys::Request) -> Result<Bytes> {
    match req.body() {
        None => Ok(Bytes::new()),
        Some(stream) => {
            let resp = web_sys::Response::new_with_opt_readable_stream(Some(&stream))
                .map_err(|e| worker::Error::RustError(format!("Response::new failed: {e:?}")))?;
            let promise = resp
                .array_buffer()
                .map_err(|e| worker::Error::RustError(format!("arrayBuffer() failed: {e:?}")))?;
            let buf = wasm_bindgen_futures::JsFuture::from(promise)
                .await
                .map_err(|e| {
                    worker::Error::RustError(format!("arrayBuffer await failed: {e:?}"))
                })?;
            let uint8 = js_sys::Uint8Array::new(&buf);
            Ok(Bytes::from(uint8.to_vec()))
        }
    }
}

/// Convert an s3s HTTP response to a web_sys::Response.
fn s3_response_to_ws(resp: http::Response<s3s::Body>) -> Result<web_sys::Response> {
    let (parts, body) = resp.into_parts();

    let ws_headers = http_headermap_to_ws_headers(&parts.headers)
        .map_err(|e| worker::Error::RustError(format!("failed to create headers: {e:?}")))?;

    let resp_init = web_sys::ResponseInit::new();
    resp_init.set_status(parts.status.as_u16());
    resp_init.set_headers(&ws_headers.into());

    // Try to get bytes directly if available, otherwise create an empty response
    // and set up streaming later if needed.
    if let Some(bytes) = body.bytes() {
        if bytes.is_empty() {
            web_sys::Response::new_with_opt_str_and_init(None, &resp_init)
                .map_err(|e| worker::Error::RustError(format!("Response::new failed: {e:?}")))
        } else {
            let uint8 = js_sys::Uint8Array::from(bytes.as_ref());
            web_sys::Response::new_with_opt_buffer_source_and_init(Some(&uint8), &resp_init)
                .map_err(|e| worker::Error::RustError(format!("Response::new failed: {e:?}")))
        }
    } else {
        // For streaming responses (e.g. GET object), we need to collect first.
        // TODO: Implement proper streaming via ReadableStream for large responses.
        // For now, we return an empty response — the body will be handled separately.
        web_sys::Response::new_with_opt_str_and_init(None, &resp_init)
            .map_err(|e| worker::Error::RustError(format!("Response::new failed: {e:?}")))
    }
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
