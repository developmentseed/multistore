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
    /// Register the STS handler on the given `path`.
    ///
    /// STS requests are identified by query parameters
    /// (`Action=AssumeRoleWithWebIdentity`), not by path, so any path
    /// can be used (e.g. `"/"` or `"/.sts"`).
    fn with_sts<C: CredentialRegistry + 'static>(
        self,
        path: &str,
        config: C,
        cache: JwksCache,
        key: Option<TokenKey>,
    ) -> Self;
}

impl StsRouterExt for Router {
    fn with_sts<C: CredentialRegistry + 'static>(
        self,
        path: &str,
        config: C,
        cache: JwksCache,
        key: Option<TokenKey>,
    ) -> Self {
        self.route(path, StsHandler { config, cache, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multistore::error::ProxyError;
    use multistore::types::{RoleConfig, StoredCredential};

    /// Minimal stub that satisfies `CredentialRegistry` without real data.
    #[derive(Clone)]
    struct EmptyRegistry;

    impl CredentialRegistry for EmptyRegistry {
        async fn get_credential(
            &self,
            _access_key_id: &str,
        ) -> Result<Option<StoredCredential>, ProxyError> {
            Ok(None)
        }
        async fn get_role(&self, _role_id: &str) -> Result<Option<RoleConfig>, ProxyError> {
            Ok(None)
        }
    }

    fn test_router() -> Router {
        let cache = JwksCache::new(reqwest::Client::new(), std::time::Duration::from_secs(60));
        Router::new().with_sts("/", EmptyRegistry, cache, None)
    }

    #[tokio::test]
    async fn sts_query_on_root_path_is_handled() {
        let router = test_router();
        let headers = http::HeaderMap::new();
        let req = RequestInfo::new(
            &http::Method::GET,
            "/",
            Some("Action=AssumeRoleWithWebIdentity&RoleArn=test&WebIdentityToken=tok"),
            &headers,
            None,
        );
        assert!(
            router.dispatch(&req).await.is_some(),
            "STS request to / must be intercepted by the router"
        );
    }

    #[tokio::test]
    async fn non_sts_query_on_root_path_falls_through() {
        let router = test_router();
        let headers = http::HeaderMap::new();
        let req = RequestInfo::new(&http::Method::GET, "/", Some("prefix=foo/"), &headers, None);
        assert!(
            router.dispatch(&req).await.is_none(),
            "non-STS request to / must fall through"
        );
    }
}
