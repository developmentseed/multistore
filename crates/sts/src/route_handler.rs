//! Route handler for STS `AssumeRoleWithWebIdentity` requests.
//!
//! Intercepts STS queries before they reach the proxy dispatch pipeline
//! and delegates to [`try_handle_sts`].

use crate::{try_handle_sts, JwksCache, TokenKey};
use multistore::registry::CredentialRegistry;
use multistore::route_handler::{
    HandlerAction, ProxyResult, RequestInfo, RouteHandler, RouteHandlerFuture,
};

/// Route handler that intercepts STS `AssumeRoleWithWebIdentity` requests.
pub struct StsRouteHandler<C> {
    config: C,
    jwks_cache: JwksCache,
    token_key: Option<TokenKey>,
}

impl<C> StsRouteHandler<C> {
    pub fn new(config: C, jwks_cache: JwksCache, token_key: Option<TokenKey>) -> Self {
        Self {
            config,
            jwks_cache,
            token_key,
        }
    }
}

impl<C: CredentialRegistry> RouteHandler for StsRouteHandler<C> {
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async move {
            let (status, xml) = try_handle_sts(
                req.query,
                &self.config,
                &self.jwks_cache,
                self.token_key.as_ref(),
            )
            .await?;

            Some(HandlerAction::Response(ProxyResult::xml(status, xml)))
        })
    }
}
