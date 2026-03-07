//! Route handler for OIDC discovery endpoints.
//!
//! Serves `/.well-known/openid-configuration` and `/.well-known/jwks.json`
//! when the proxy is configured as an OIDC provider.

use crate::discovery::openid_configuration_json;
use crate::jwks::jwks_json;
use crate::jwt::JwtSigner;
use multistore::route_handler::{ProxyResult, RequestInfo, RouteHandler, RouteHandlerFuture};
use multistore::router::Router;

/// Handler that serves the OpenID Connect discovery document.
struct OidcConfigHandler {
    issuer: String,
    jwks_uri: String,
}

impl RouteHandler for OidcConfigHandler {
    fn get<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        let json = openid_configuration_json(&self.issuer, &self.jwks_uri);
        Box::pin(async move { Some(ProxyResult::json(200, json)) })
    }
}

/// Handler that serves the JWKS (JSON Web Key Set) document.
struct OidcJwksHandler {
    signer: JwtSigner,
}

impl RouteHandler for OidcJwksHandler {
    fn get<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        let json = jwks_json(self.signer.public_key(), self.signer.kid());
        Box::pin(async move { Some(ProxyResult::json(200, json)) })
    }
}

/// Extension trait for registering OIDC discovery routes on a [`Router`].
pub trait OidcRouterExt {
    /// Register `/.well-known/openid-configuration` and `/.well-known/jwks.json`
    /// routes backed by the given issuer and signer.
    fn with_oidc_discovery(self, issuer: String, signer: JwtSigner) -> Self;
}

impl OidcRouterExt for Router {
    fn with_oidc_discovery(self, issuer: String, signer: JwtSigner) -> Self {
        let jwks_uri = format!("{}/.well-known/jwks.json", issuer);

        self.route(
            "/.well-known/openid-configuration",
            OidcConfigHandler { issuer, jwks_uri },
        )
        .route("/.well-known/jwks.json", OidcJwksHandler { signer })
    }
}
