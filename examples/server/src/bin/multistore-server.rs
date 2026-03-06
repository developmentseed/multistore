//! Multistore Proxy Server binary.
//!
//! Usage:
//!     multistore-server --config config.toml [--listen 0.0.0.0:8080] [--domain s3.local]

use multistore::sealed_token::TokenKey;
use multistore_server::cached::CachedProvider;
use multistore_server::server::{run, ServerConfig};
use multistore_static_config::StaticProvider;
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multistore=info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    let config_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("config.toml");

    let listen_addr: SocketAddr = args
        .iter()
        .position(|a| a == "--listen")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| ([0, 0, 0, 0], 8080).into());

    let domain = args
        .iter()
        .position(|a| a == "--domain")
        .and_then(|i| args.get(i + 1))
        .cloned();

    tracing::info!(config = %config_path, listen = %listen_addr, "starting multistore-server");

    let base_config = StaticProvider::from_file(config_path)?;
    let config = CachedProvider::new(base_config, Duration::from_secs(60));

    let token_key = std::env::var("SESSION_TOKEN_KEY")
        .ok()
        .map(|v| TokenKey::from_base64(&v))
        .transpose()?;

    let oidc_provider_key = std::env::var("OIDC_PROVIDER_KEY").ok();
    let oidc_provider_issuer = std::env::var("OIDC_PROVIDER_ISSUER").ok();

    let server_config = ServerConfig {
        listen_addr,
        virtual_host_domain: domain,
        token_key,
        oidc_provider_key,
        oidc_provider_issuer,
    };

    run(config.clone(), config, server_config).await
}
