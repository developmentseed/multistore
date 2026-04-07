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
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        if req.method.as_str() != "GET" {
            return Box::pin(async { None });
        }
        let json = openid_configuration_json(&self.issuer, &self.jwks_uri);
        Box::pin(async move { Some(ProxyResult::json(200, json)) })
    }
}

/// Handler that serves the JWKS (JSON Web Key Set) document.
struct OidcJwksHandler {
    signers: Vec<JwtSigner>,
}

impl RouteHandler for OidcJwksHandler {
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        if req.method.as_str() != "GET" {
            return Box::pin(async { None });
        }
        let keys: Vec<_> = self
            .signers
            .iter()
            .map(|s| (s.public_key(), s.kid()))
            .collect();
        let json = jwks_json(&keys);
        Box::pin(async move { Some(ProxyResult::json(200, json)) })
    }
}

/// Extension trait for registering OIDC discovery routes on a [`Router`].
pub trait OidcRouterExt {
    /// Register `/.well-known/openid-configuration` and `/.well-known/jwks.json`
    /// routes backed by the given issuer and signer.
    ///
    /// `additional_signers` contains previous keys that should still appear in
    /// the JWKS for key rotation (they are not used for signing new tokens).
    fn with_oidc_discovery(self, issuer: String, signers: Vec<JwtSigner>) -> Self;
}

impl OidcRouterExt for Router {
    fn with_oidc_discovery(self, issuer: String, signers: Vec<JwtSigner>) -> Self {
        let jwks_uri = format!("{}/.well-known/jwks.json", issuer);

        self.route(
            "/.well-known/openid-configuration",
            OidcConfigHandler { issuer, jwks_uri },
        )
        .route("/.well-known/jwks.json", OidcJwksHandler { signers })
    }
}
