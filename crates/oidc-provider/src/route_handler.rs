//! Route handler for OIDC discovery endpoints.
//!
//! Serves `/.well-known/openid-configuration` and `/.well-known/jwks.json`
//! when the proxy is configured as an OIDC provider.

use crate::discovery::openid_configuration_json;
use crate::jwks::jwks_json;
use crate::jwt::JwtSigner;
use multistore::proxy::{HandlerAction, ProxyResult};
use multistore::route_handler::{RequestInfo, RouteHandler, RouteHandlerFuture};

/// Serves OIDC discovery documents for the proxy's identity provider.
pub struct OidcDiscoveryRouteHandler {
    issuer: String,
    signer: JwtSigner,
}

impl OidcDiscoveryRouteHandler {
    pub fn new(issuer: String, signer: JwtSigner) -> Self {
        Self { issuer, signer }
    }
}

impl RouteHandler for OidcDiscoveryRouteHandler {
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async move {
            let json = match req.path {
                "/.well-known/openid-configuration" => {
                    let jwks_uri = format!("{}/.well-known/jwks.json", self.issuer);
                    openid_configuration_json(&self.issuer, &jwks_uri)
                }
                "/.well-known/jwks.json" => {
                    jwks_json(self.signer.public_key(), self.signer.kid())
                }
                _ => return None,
            };

            Some(HandlerAction::Response(ProxyResult::json(200, json)))
        })
    }
}
