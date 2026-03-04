//! AWS Lambda runtime for the multistore S3 proxy.
//!
//! Mirrors the server example but runs inside AWS Lambda instead of a
//! standalone Tokio/Hyper server.
//!
//! ## Building
//!
//! ```sh
//! cargo lambda build --release -p multistore-lambda
//! ```
//!
//! ## Environment Variables
//!
//! - `CONFIG_PATH` — Path to the TOML config file (default: `config.toml`)
//! - `STS_CONFIG_PATH` — Optional separate STS config file
//! - `VIRTUAL_HOST_DOMAIN` — Domain for virtual-hosted-style requests
//! - `SESSION_TOKEN_KEY` — Base64-encoded AES-256-GCM key for session tokens
//! - `OIDC_PROVIDER_KEY` — PEM-encoded RSA private key for OIDC provider
//! - `OIDC_PROVIDER_ISSUER` — OIDC issuer URL

mod client;

use client::{LambdaBackend, ReqwestHttpExchange};
use lambda_http::{service_fn, Body, Error, Request, Response};
use multistore::config::static_file::StaticProvider;
use multistore::proxy::{ForwardRequest, Gateway, GatewayResponse, RESPONSE_HEADER_ALLOWLIST};
use multistore::resolver::DefaultResolver;
use multistore::response_body::ProxyResponseBody;
use multistore::route_handler::RequestInfo;
use multistore::sealed_token::TokenKey;
use multistore_oidc_provider::backend_auth::MaybeOidcAuth;
use multistore_oidc_provider::jwt::JwtSigner;
use multistore_oidc_provider::route_handler::OidcDiscoveryRouteHandler;
use multistore_oidc_provider::OidcCredentialProvider;
use multistore_sts::route_handler::StsRouteHandler;
use multistore_sts::JwksCache;
use std::sync::OnceLock;
use std::time::Duration;

type OidcAuth = MaybeOidcAuth<ReqwestHttpExchange>;
type Handler = Gateway<LambdaBackend, DefaultResolver<StaticProvider>, OidcAuth>;

struct AppState {
    handler: Handler,
    reqwest_client: reqwest::Client,
}

static STATE: OnceLock<AppState> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multistore=info".into()),
        )
        .with_ansi(false)
        .init();

    let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".into());
    let sts_config_path = std::env::var("STS_CONFIG_PATH").ok();
    let domain = std::env::var("VIRTUAL_HOST_DOMAIN").ok();

    let config = StaticProvider::from_file(&config_path)?;
    let sts_config = match sts_config_path {
        Some(path) => StaticProvider::from_file(&path)?,
        None => config.clone(),
    };

    let token_key = std::env::var("SESSION_TOKEN_KEY")
        .ok()
        .map(|v| TokenKey::from_base64(&v))
        .transpose()?;

    let backend = LambdaBackend::new();
    let reqwest_client = backend.client().clone();
    let jwks_cache = JwksCache::new(reqwest_client.clone(), Duration::from_secs(900));
    let resolver = DefaultResolver::new(config, domain, token_key.clone());

    let oidc_provider_key = std::env::var("OIDC_PROVIDER_KEY").ok();
    let oidc_provider_issuer = std::env::var("OIDC_PROVIDER_ISSUER").ok();

    let (oidc_auth, oidc_discovery) = match (&oidc_provider_key, &oidc_provider_issuer) {
        (Some(key_pem), Some(issuer)) => {
            let signer = JwtSigner::from_pem(key_pem, "proxy-key-1".into(), 300)
                .map_err(|e| format!("failed to create OIDC JWT signer: {e}"))?;
            let http = ReqwestHttpExchange::new(reqwest_client.clone());
            let provider = OidcCredentialProvider::new(
                signer.clone(),
                http,
                issuer.clone(),
                "sts.amazonaws.com".into(),
            );
            let auth = MaybeOidcAuth::Enabled(Box::new(
                multistore_oidc_provider::backend_auth::AwsOidcBackendAuth::new(provider),
            ));
            let discovery = OidcDiscoveryRouteHandler::new(issuer.clone(), signer);
            (auth, Some(discovery))
        }
        _ => (MaybeOidcAuth::Disabled, None),
    };

    // Build the gateway with route handlers (OIDC discovery first, then STS).
    let mut handler = Gateway::new(backend, resolver).with_oidc_auth(oidc_auth);
    if let Some(discovery) = oidc_discovery {
        handler = handler.with_route_handler(discovery);
    }
    handler = handler.with_route_handler(StsRouteHandler::new(sts_config, jwks_cache, token_key));

    let _ = STATE.set(AppState {
        handler,
        reqwest_client,
    });

    lambda_http::run(service_fn(request_handler)).await
}

async fn request_handler(req: Request) -> Result<Response<Body>, Error> {
    let state = STATE.get().expect("state not initialized");
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let path = uri.path().to_string();
    let query = uri.query().map(|q| q.to_string());
    let headers = parts.headers;

    tracing::debug!(method = %method, uri = %uri, "incoming request");

    let req_info = RequestInfo {
        method: &method,
        path: &path,
        query: query.as_deref(),
        headers: &headers,
    };

    Ok(
        match state
            .handler
            .handle_request(&req_info, body, |b| async {
                body_to_bytes(b).await.map_err(|e| e.to_string())
            })
            .await
        {
            GatewayResponse::Response(result) => build_lambda_response(result),
            GatewayResponse::Forward(fwd, body) => {
                forward_to_backend(&state.reqwest_client, fwd, body).await
            }
        },
    )
}

/// Convert a `ProxyResult` to a Lambda `Response`.
fn build_lambda_response(result: multistore::proxy::ProxyResult) -> Response<Body> {
    let body = match result.body {
        ProxyResponseBody::Bytes(b) => Body::Binary(b.to_vec()),
        ProxyResponseBody::Empty => Body::Empty,
    };

    let mut builder = Response::builder().status(result.status);
    for (key, value) in result.headers.iter() {
        builder = builder.header(key, value);
    }

    builder.body(body).unwrap()
}

/// Build a plain-text error response.
fn error_response(status: u16, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::Text(message.to_string()))
        .unwrap()
}

/// Execute a Forward request via reqwest, buffering the response for Lambda.
async fn forward_to_backend(
    client: &reqwest::Client,
    fwd: ForwardRequest,
    body: Body,
) -> Response<Body> {
    let mut req_builder = client.request(fwd.method.clone(), fwd.url.as_str());

    for (k, v) in fwd.headers.iter() {
        req_builder = req_builder.header(k, v);
    }

    // Attach body for PUT requests
    if fwd.method == http::Method::PUT {
        match body_to_bytes(body).await {
            Ok(bytes) => {
                req_builder = req_builder.body(bytes);
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to read PUT body");
                return error_response(502, "Bad Gateway");
            }
        }
    }

    let backend_resp = match req_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!(error = %e, "forward request failed");
            return error_response(502, "Bad Gateway");
        }
    };

    let status = backend_resp.status().as_u16();

    // Forward allowlisted response headers
    let mut resp_headers = http::HeaderMap::new();
    for name in RESPONSE_HEADER_ALLOWLIST {
        if let Some(v) = backend_resp.headers().get(*name) {
            resp_headers.insert(*name, v.clone());
        }
    }

    // Buffer the response body (Lambda doesn't support streaming responses)
    let body_bytes = match backend_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to read backend response body");
            return error_response(502, "Bad Gateway");
        }
    };

    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        builder = builder.header(k, v);
    }

    builder.body(Body::Binary(body_bytes.to_vec())).unwrap()
}

/// Collect a Lambda body into bytes.
async fn body_to_bytes(body: Body) -> Result<bytes::Bytes, Box<dyn std::error::Error>> {
    match body {
        Body::Empty => Ok(bytes::Bytes::new()),
        Body::Text(s) => Ok(bytes::Bytes::from(s)),
        Body::Binary(b) => Ok(bytes::Bytes::from(b)),
    }
}
