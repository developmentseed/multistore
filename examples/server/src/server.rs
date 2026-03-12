//! HTTP server using s3s service layer.

use crate::client::ServerBackend;
use multistore::registry::{BucketRegistry, CredentialRegistry};
use multistore::service::{MultistoreAccess, MultistoreAuth, MultistoreService};
use multistore_sts::TokenKey;
use s3s::service::S3ServiceBuilder;
use std::net::SocketAddr;
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

/// Run the S3 proxy server using s3s service layer.
///
/// Uses s3s's built-in S3 protocol handling with `MultistoreService`.
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

    // Build the s3s service
    let service = MultistoreService::new(bucket_registry, backend);
    let auth = MultistoreAuth::new(credential_registry);

    let mut builder = S3ServiceBuilder::new(service);
    builder.set_auth(auth);
    builder.set_access(MultistoreAccess);

    if let Some(ref domain) = server_config.virtual_host_domain {
        builder.set_host(
            s3s::host::SingleDomain::new(domain)
                .map_err(|e| format!("invalid virtual host domain: {e}"))?,
        );
    }

    let s3_service = builder.build();

    // Use the s3s service directly with hyper
    let listener = TcpListener::bind(server_config.listen_addr).await?;
    tracing::info!("listening on {}", server_config.listen_addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let s3_service = s3_service.clone();

        tokio::spawn(async move {
            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, s3_service)
                    .await
            {
                tracing::error!("connection error: {e}");
            }
        });
    }
}
