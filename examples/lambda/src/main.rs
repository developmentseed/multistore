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
//! - `VIRTUAL_HOST_DOMAIN` — Domain for virtual-hosted-style requests
//! - `SESSION_TOKEN_KEY` — Base64-encoded AES-256-GCM key for session tokens
//! - `OIDC_PROVIDER_KEY` — PEM-encoded RSA private key for OIDC provider
//! - `OIDC_PROVIDER_ISSUER` — OIDC issuer URL

mod client;

use client::{LambdaBackend, ReqwestHttpExchange};
use lambda_http::{service_fn, Body, Error, Request, Response};
use multistore::error::ProxyError;
use multistore::forwarder::{ForwardResponse, Forwarder};
use multistore::proxy::{GatewayResponse, ProxyGateway};
use multistore::route_handler::{
    ForwardRequest, ProxyResponseBody, ProxyResult, RequestInfo, RESPONSE_HEADER_ALLOWLIST,
};
use multistore::router::Router;
use multistore_oidc_provider::backend_auth::MaybeOidcAuth;
use multistore_oidc_provider::jwt::JwtSigner;
use multistore_oidc_provider::route_handler::OidcRouterExt;
use multistore_oidc_provider::OidcCredentialProvider;
use multistore_static_config::StaticProvider;
use multistore_sts::route_handler::StsRouterExt;
use multistore_sts::JwksCache;
use multistore_sts::TokenKey;
use std::sync::OnceLock;
use std::time::Duration;

/// Forwards presigned requests to the backend using `reqwest`, buffering the
/// full response body for Lambda (which does not support streaming responses).
struct LambdaForwarder {
    client: reqwest::Client,
}

impl Forwarder<Body> for LambdaForwarder {
    type ResponseBody = Body;

    async fn forward(
        &self,
        request: ForwardRequest,
        body: Body,
    ) -> Result<ForwardResponse<Self::ResponseBody>, ProxyError> {
        let mut req_builder = self
            .client
            .request(request.method.clone(), request.url.as_str());

        for (k, v) in request.headers.iter() {
            req_builder = req_builder.header(k, v);
        }

        // Attach body for PUT requests
        if request.method == http::Method::PUT {
            let bytes = body_to_bytes(body)
                .await
                .map_err(|e| ProxyError::Internal(format!("failed to read PUT body: {e}")))?;
            req_builder = req_builder.body(bytes);
        }

        let backend_resp = req_builder
            .send()
            .await
            .map_err(|e| ProxyError::Internal(format!("forward request failed: {e}")))?;

        let status = backend_resp.status().as_u16();

        // Forward allowlisted response headers
        let mut headers = http::HeaderMap::new();
        for name in RESPONSE_HEADER_ALLOWLIST {
            if let Some(v) = backend_resp.headers().get(*name) {
                headers.insert(*name, v.clone());
            }
        }

        let content_length = backend_resp.content_length();

        // Buffer the response body (Lambda doesn't support streaming responses)
        let body_bytes = backend_resp
            .bytes()
            .await
            .map_err(|e| ProxyError::Internal(format!("failed to read backend response: {e}")))?;

        Ok(ForwardResponse {
            status,
            headers,
            body: Body::Binary(body_bytes.to_vec()),
            content_length,
        })
    }
}

type Handler = ProxyGateway<LambdaBackend, LambdaForwarder>;

struct AppState {
    handler: Handler,
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
    let domain = std::env::var("VIRTUAL_HOST_DOMAIN").ok();

    let config = StaticProvider::from_file(&config_path)?;

    let token_key = std::env::var("SESSION_TOKEN_KEY")
        .ok()
        .map(|v| TokenKey::from_base64(&v))
        .transpose()?;

    let backend = LambdaBackend::new();
    let reqwest_client = backend.client().clone();
    let jwks_cache = JwksCache::new(reqwest_client.clone(), Duration::from_secs(900));
    let sts_creds = config.clone();

    let oidc_provider_key = std::env::var("OIDC_PROVIDER_KEY").ok();
    let oidc_provider_issuer = std::env::var("OIDC_PROVIDER_ISSUER").ok();

    let (oidc_auth, oidc_signer, oidc_issuer) = match (&oidc_provider_key, &oidc_provider_issuer) {
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
                multistore_oidc_provider::backend_auth::AwsBackendAuth::new(provider),
            ));
            (auth, Some(signer), Some(issuer.clone()))
        }
        _ => (MaybeOidcAuth::Disabled, None, None),
    };

    // Build router with OIDC discovery (if configured) and STS.
    let mut router = Router::new();
    if let (Some(signer), Some(issuer)) = (oidc_signer, oidc_issuer) {
        router = router.with_oidc_discovery(issuer, signer);
    }
    router = router.with_sts(sts_creds, jwks_cache, token_key.clone());

    let forwarder = LambdaForwarder {
        client: reqwest_client,
    };

    // Build the gateway with CORS (before auth) and S3 defaults.
    let mut handler = ProxyGateway::new(backend, forwarder, domain.clone());
    handler = handler.with_middleware(multistore::cors::CorsMiddleware::new(
        config.clone(),
        domain,
    ));
    if let Some(resolver) = token_key {
        handler = handler.with_s3_defaults_and_resolver(config.clone(), config, resolver);
    } else {
        handler = handler.with_s3_defaults(config.clone(), config);
    }
    handler = handler.with_middleware(oidc_auth).with_middleware(router);

    let _ = STATE.set(AppState { handler });

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

    let req_info = RequestInfo::new(&method, &path, query.as_deref(), &headers, None);

    Ok(
        match state
            .handler
            .handle_request(&req_info, body, |b| async {
                body_to_bytes(b).await.map_err(|e| e.to_string())
            })
            .await
        {
            GatewayResponse::Response(result) => build_lambda_response(result),
            GatewayResponse::Forward(resp) => {
                let mut builder = Response::builder().status(resp.status);
                for (k, v) in resp.headers.iter() {
                    builder = builder.header(k, v);
                }
                builder.body(resp.body).unwrap()
            }
        },
    )
}

/// Convert a `ProxyResult` to a Lambda `Response`.
fn build_lambda_response(result: ProxyResult) -> Response<Body> {
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

/// Collect a Lambda body into bytes.
async fn body_to_bytes(body: Body) -> Result<bytes::Bytes, Box<dyn std::error::Error>> {
    match body {
        Body::Empty => Ok(bytes::Bytes::new()),
        Body::Text(s) => Ok(bytes::Bytes::from(s)),
        Body::Binary(b) => Ok(bytes::Bytes::from(b)),
    }
}
