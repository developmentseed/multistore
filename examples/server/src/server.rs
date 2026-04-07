//! HTTP server using axum, wiring everything together.

use crate::axum_helpers::build_proxy_response;
use crate::client::{ReqwestHttpExchange, ServerBackend};
use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use axum::Router;
use multistore::backend::ForwardResponse;
use multistore::proxy::{GatewayResponse, ProxyGateway};
use multistore::registry::{BucketRegistry, CredentialRegistry};
use multistore::route_handler::RequestInfo;
use multistore::router::Router as ProxyRouter;
use multistore_oidc_provider::backend_auth::MaybeOidcAuth;
use multistore_oidc_provider::jwt::JwtSigner;
use multistore_oidc_provider::route_handler::OidcRouterExt;
use multistore_oidc_provider::OidcCredentialProvider;
use multistore_sts::route_handler::StsRouterExt;
use multistore_sts::JwksCache;
use multistore_sts::TokenKey;
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

struct AppState<R: BucketRegistry, C: CredentialRegistry> {
    handler: ProxyGateway<ServerBackend, R, C>,
}

/// Run the S3 proxy server.
///
/// # Example
///
/// ```rust,ignore
/// use multistore_static_config::StaticProvider;
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
///     run(config.clone(), config, server_config).await.unwrap();
/// }
/// ```
pub async fn run<R, C>(
    bucket_registry: R,
    credential_registry: C,
    server_config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: BucketRegistry,
    C: CredentialRegistry,
{
    let backend = ServerBackend::new();
    let reqwest_client = backend.client().clone();
    let jwks_cache = JwksCache::new(reqwest_client.clone(), Duration::from_secs(900));
    let token_key = server_config.token_key;
    let sts_creds = credential_registry.clone();

    // Build OIDC provider if both key and issuer are configured.
    let (oidc_auth, oidc_signer, oidc_issuer) = match (
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
                multistore_oidc_provider::backend_auth::AwsBackendAuth::new(provider),
            ));
            (auth, Some(signer), Some(issuer.clone()))
        }
        _ => (MaybeOidcAuth::Disabled, None, None),
    };

    // Build router with OIDC discovery (if configured) and STS.
    let mut proxy_router = ProxyRouter::new();
    if let (Some(signer), Some(issuer)) = (oidc_signer, oidc_issuer) {
        proxy_router = proxy_router.with_oidc_discovery(issuer, vec![signer]);
    }
    proxy_router = proxy_router.with_sts(sts_creds, jwks_cache, token_key.clone());

    // Build the gateway with the router.
    let mut handler = ProxyGateway::new(
        backend,
        bucket_registry,
        credential_registry,
        server_config.virtual_host_domain,
    )
    .with_middleware(oidc_auth)
    .with_router(proxy_router);
    if let Some(ref resolver) = token_key {
        handler = handler.with_credential_resolver(resolver.clone());
    }

    let state = Arc::new(AppState { handler });

    let app = Router::new()
        .fallback(request_handler::<R, C>)
        .with_state(state);

    let listener = TcpListener::bind(server_config.listen_addr).await?;
    tracing::info!("listening on {}", server_config.listen_addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn request_handler<R: BucketRegistry, C: CredentialRegistry>(
    State(state): State<Arc<AppState<R, C>>>,
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

    let req_info = RequestInfo::new(&method, &path, query.as_deref(), &headers, None);

    match state
        .handler
        .handle_request(&req_info, body, |b| axum::body::to_bytes(b, usize::MAX))
        .await
    {
        GatewayResponse::Response(result) => build_proxy_response(result),
        GatewayResponse::Forward(ForwardResponse {
            status,
            headers,
            body: backend_resp,
            ..
        }) => {
            // Stream the response body from the reqwest::Response
            let body = Body::from_stream(backend_resp.bytes_stream());

            let mut builder = Response::builder().status(status);
            for (k, v) in headers.iter() {
                builder = builder.header(k, v);
            }

            builder.body(body).unwrap()
        }
    }
}
