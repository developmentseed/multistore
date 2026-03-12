//! AWS Lambda runtime for the multistore S3 proxy.
//!
//! Uses s3s for S3 protocol handling with `MultistoreService`.
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

mod client;

use client::LambdaBackend;
use lambda_http::{service_fn, Body, Error, Request, Response};
use multistore::service::{MultistoreAccess, MultistoreAuth, MultistoreService};
use multistore_static_config::StaticProvider;
use s3s::service::S3ServiceBuilder;
use std::sync::OnceLock;

struct AppState {
    s3_service: s3s::service::S3Service,
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

    let backend = LambdaBackend::new();

    // Build the s3s service
    let service = MultistoreService::new(config.clone(), backend);
    let auth = MultistoreAuth::new(config);

    let mut builder = S3ServiceBuilder::new(service);
    builder.set_auth(auth);
    builder.set_access(MultistoreAccess);

    if let Some(ref d) = domain {
        builder.set_host(
            s3s::host::SingleDomain::new(d)
                .map_err(|e| format!("invalid virtual host domain: {e}"))?,
        );
    }

    let s3_service = builder.build();

    let _ = STATE.set(AppState { s3_service });

    lambda_http::run(service_fn(request_handler)).await
}

async fn request_handler(req: Request) -> Result<Response<Body>, Error> {
    let state = STATE.get().expect("state not initialized");

    // Convert lambda_http::Request to http::Request<s3s::Body>
    let (parts, body) = req.into_parts();
    let body_bytes = match body {
        Body::Empty => bytes::Bytes::new(),
        Body::Text(s) => bytes::Bytes::from(s),
        Body::Binary(b) => bytes::Bytes::from(b),
    };
    let s3_req = http::Request::from_parts(parts, s3s::Body::from(body_bytes));

    // Call the s3s service
    let s3_resp = state
        .s3_service
        .call(s3_req)
        .await
        .map_err(|e| format!("s3s error: {e:?}"))?;

    // Convert http::Response<s3s::Body> to lambda_http::Response<Body>
    let (parts, s3_body) = s3_resp.into_parts();
    let resp_bytes = http_body_util::BodyExt::collect(s3_body)
        .await
        .map_err(|e| format!("failed to collect response body: {e}"))?
        .to_bytes();

    let lambda_body = if resp_bytes.is_empty() {
        Body::Empty
    } else {
        Body::Binary(resp_bytes.to_vec())
    };

    Ok(Response::from_parts(parts, lambda_body))
}
