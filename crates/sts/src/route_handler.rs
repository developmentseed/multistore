//! Route handler for STS `AssumeRoleWithWebIdentity` requests.
//!
//! Intercepts STS queries before they reach the proxy dispatch pipeline
//! and delegates to [`try_handle_sts`].

use crate::{try_handle_sts, JwksCache, TokenKey};
use multistore::registry::CredentialRegistry;
use multistore::route_handler::{ProxyResult, RequestInfo, RouteHandler, RouteHandlerFuture};
use multistore::router::Router;

/// Handler that intercepts `AssumeRoleWithWebIdentity` STS requests.
struct StsHandler<C> {
    config: C,
    cache: JwksCache,
    key: Option<TokenKey>,
}

impl<C: CredentialRegistry> RouteHandler for StsHandler<C> {
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async move {
            let (status, xml) =
                try_handle_sts(req.query, &self.config, &self.cache, self.key.as_ref()).await?;
            Some(ProxyResult::xml(status, xml))
        })
    }
}

/// Extension trait for registering STS routes on a [`Router`].
pub trait StsRouterExt {
    /// Register a catch-all STS handler that intercepts
    /// `AssumeRoleWithWebIdentity` requests on any path.
    fn with_sts<C: CredentialRegistry + 'static>(
        self,
        config: C,
        cache: JwksCache,
        key: Option<TokenKey>,
    ) -> Self;
}

impl StsRouterExt for Router {
    fn with_sts<C: CredentialRegistry + 'static>(
        self,
        config: C,
        cache: JwksCache,
        key: Option<TokenKey>,
    ) -> Self {
        self.route("/{*path}", StsHandler { config, cache, key })
    }
}
