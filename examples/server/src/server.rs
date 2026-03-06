//! HTTP server using axum, wiring everything together.

use crate::axum_helpers::{build_proxy_response, error_response};
use crate::client::{ReqwestHttpExchange, ServerBackend};
use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::Router;
use futures::TryStreamExt;
use http::HeaderMap;
use http_body_util::BodyStream;
use multistore::config::ConfigProvider;
use multistore::proxy::{Gateway, GatewayResponse};
use multistore::resolver::DefaultResolver;
use multistore::route_handler::{ForwardRequest, RequestInfo, RESPONSE_HEADER_ALLOWLIST};
use multistore::sealed_token::TokenKey;
use multistore_oidc_provider::backend_auth::MaybeOidcAuth;
use multistore_oidc_provider::jwt::JwtSigner;
use multistore_oidc_provider::route_handler::OidcDiscoveryRouteHandler;
use multistore_oidc_provider::OidcCredentialProvider;
use multistore_sts::route_handler::StsRouteHandler;
use multistore_sts::JwksCache;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Server configuration.
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    /// The base domain for virtual-hosted-style requests (e.g., "s3.example.com").
    /// If set, requests to `{bucket}.s3.example.com` use virtual-hosted style.
    pub virtual_host_domain: Option<String>,
    /// Optional AES-256-GCM key for self-contained encrypted session tokens.
    pub token_key: Option<TokenKey>,
    /// PEM-encoded RSA private key for OIDC provider (minting JWTs for backend auth).
    pub oidc_provider_key: Option<String>,
    /// Issuer URL for the OIDC provider (must be publicly reachable for JWKS discovery).
    pub oidc_provider_issuer: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([0, 0, 0, 0], 8080).into(),
            virtual_host_domain: None,
            token_key: None,
            oidc_provider_key: None,
            oidc_provider_issuer: None,
        }
    }
}

type OidcAuth = MaybeOidcAuth<ReqwestHttpExchange>;

struct AppState<P: ConfigProvider> {
    handler: Gateway<ServerBackend, DefaultResolver<P>, OidcAuth>,
    reqwest_client: reqwest::Client,
}

/// Run the S3 proxy server.
///
/// # Example
///
/// ```rust,ignore
/// use multistore::config::static_file::StaticProvider;
/// use multistore_server::server::{run, ServerConfig};
///
/// #[tokio::main]
/// async fn main() {
///     let config = StaticProvider::from_file("config.toml").unwrap();
///     let server_config = ServerConfig {
///         listen_addr: ([0, 0, 0, 0], 8080).into(),
///         virtual_host_domain: Some("s3.local".to_string()),
///         ..Default::default()
///     };
///     run(config, server_config).await.unwrap();
/// }
/// ```
pub async fn run<P>(
    config: P,
    server_config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>>
where
    P: ConfigProvider + Clone + Send + Sync + 'static,
{
    let backend = ServerBackend::new();
    let reqwest_client = backend.client().clone();
    let jwks_cache = JwksCache::new(reqwest_client.clone(), Duration::from_secs(900));
    let token_key = server_config.token_key;
    let sts_config = config.clone();
    let resolver =
        DefaultResolver::new(config, server_config.virtual_host_domain, token_key.clone());

    // Build OIDC provider if both key and issuer are configured.
    let (oidc_auth, oidc_discovery) = match (
        &server_config.oidc_provider_key,
        &server_config.oidc_provider_issuer,
    ) {
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

    let state = Arc::new(AppState {
        handler,
        reqwest_client,
    });

    let app = Router::new()
        .fallback(request_handler::<P>)
        .with_state(state);

    let listener = TcpListener::bind(server_config.listen_addr).await?;
    tracing::info!("listening on {}", server_config.listen_addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn request_handler<P: ConfigProvider + Send + Sync + 'static>(
    State(state): State<Arc<AppState<P>>>,
    req: axum::extract::Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let path = uri.path().to_string();
    let query = uri.query().map(|q| q.to_string());
    let headers = parts.headers;

    tracing::debug!(
        method = %method,
        uri = %uri,
        "incoming request"
    );

    let req_info = RequestInfo {
        method: &method,
        path: &path,
        query: query.as_deref(),
        headers: &headers,
    };

    match state
        .handler
        .handle_request(&req_info, body, |b| axum::body::to_bytes(b, usize::MAX))
        .await
    {
        GatewayResponse::Response(result) => build_proxy_response(result),
        GatewayResponse::Forward(fwd, body) => {
            forward_to_backend(&state.reqwest_client, fwd, body).await
        }
    }
}

/// Execute a Forward request via reqwest, streaming both request and response bodies.
async fn forward_to_backend(client: &reqwest::Client, fwd: ForwardRequest, body: Body) -> Response {
    let mut req_builder = client.request(fwd.method.clone(), fwd.url.as_str());

    for (k, v) in fwd.headers.iter() {
        req_builder = req_builder.header(k, v);
    }

    // Attach streaming body for PUT
    if fwd.method == http::Method::PUT {
        let body_stream =
            BodyStream::new(body).try_filter_map(|frame| async move { Ok(frame.into_data().ok()) });
        req_builder = req_builder.body(reqwest::Body::wrap_stream(body_stream));
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
    let mut resp_headers = HeaderMap::new();
    for name in RESPONSE_HEADER_ALLOWLIST {
        if let Some(v) = backend_resp.headers().get(*name) {
            resp_headers.insert(*name, v.clone());
        }
    }

    // Stream the response body
    let body = Body::from_stream(backend_resp.bytes_stream());

    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        builder = builder.header(k, v);
    }

    builder.body(body).unwrap()
}
