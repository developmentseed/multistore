//! Route handler for STS `AssumeRoleWithWebIdentity` requests.
//!
//! Intercepts STS queries before they reach the proxy dispatch pipeline
//! and delegates to [`try_handle_sts`].

use crate::{
    handle_get_caller_identity, is_get_caller_identity, try_handle_sts, JwksCache, TokenKey,
};
use multistore::registry::CredentialRegistry;
use multistore::route_handler::{ProxyResult, RequestInfo, RouteHandler, RouteHandlerFuture};
use multistore::router::Router;

/// Handler that intercepts STS `AssumeRoleWithWebIdentity` and
/// `GetCallerIdentity` requests.
struct StsHandler<C> {
    config: C,
    cache: JwksCache,
    key: Option<TokenKey>,
}

impl<C: CredentialRegistry> RouteHandler for StsHandler<C> {
    fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async move {
            // GetCallerIdentity is authenticated (SigV4 over the temporary
            // credentials) and needs the full request, so it is dispatched
            // before the unauthenticated AssumeRoleWithWebIdentity exchange.
            if is_get_caller_identity(req.query) || is_get_caller_identity(req.form_body) {
                let (status, xml) = handle_get_caller_identity(req, self.key.as_ref());
                return Some(ProxyResult::xml(status, xml));
            }
            let (status, xml) = try_handle_sts(
                req.query,
                req.form_body,
                &self.config,
                &self.cache,
                self.key.as_ref(),
            )
            .await?;
            Some(ProxyResult::xml(status, xml))
        })
    }
}

/// Extension trait for registering STS routes on a [`Router`].
pub trait StsRouterExt {
    /// Register the STS handler on the given `path`.
    ///
    /// STS requests are identified by their parameters (`Action=...`) — in the
    /// query string or, as AWS SDKs send them, in a form-encoded `POST` body
    /// surfaced via [`RequestInfo::form_body`] — not by path, so any path can be
    /// used (e.g. `"/"` or `"/.sts"`). Runtimes must populate `form_body` for
    /// form-encoded `POST`s or SDK clients will fall through unhandled.
    ///
    /// The handler is registered on both `path` and its trailing-slash variant
    /// (`/.sts` and `/.sts/`). AWS SDK JS v3 — the STS client inside
    /// `aws-actions/configure-aws-credentials` — appends a trailing slash to the
    /// configured endpoint path, so its requests arrive at `/.sts/`; without the
    /// second route they would miss the handler entirely.
    fn with_sts<C: CredentialRegistry + Clone + 'static>(
        self,
        path: &str,
        config: C,
        cache: JwksCache,
        key: Option<TokenKey>,
    ) -> Self;
}

impl StsRouterExt for Router {
    fn with_sts<C: CredentialRegistry + Clone + 'static>(
        self,
        path: &str,
        config: C,
        cache: JwksCache,
        key: Option<TokenKey>,
    ) -> Self {
        let router = self.route(
            path,
            StsHandler {
                config: config.clone(),
                cache: cache.clone(),
                key: key.clone(),
            },
        );
        // Also accept the trailing-slash form (see doc comment). Skip it when
        // `path` already ends in `/` to avoid registering the same route twice
        // (matchit panics on a duplicate).
        let with_slash = format!("{}/", path.trim_end_matches('/'));
        if with_slash == path {
            router
        } else {
            router.route(&with_slash, StsHandler { config, cache, key })
        }
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

    #[tokio::test]
    async fn sts_form_body_post_is_handled() {
        // AWS SDKs send AssumeRoleWithWebIdentity as a form-encoded POST body
        // with no query string at all.
        let router = test_router();
        let headers = http::HeaderMap::new();
        let req = RequestInfo::new(&http::Method::POST, "/", None, &headers, None)
            .with_form_body(Some(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=test&WebIdentityToken=tok",
        ));
        assert!(
            router.dispatch(&req).await.is_some(),
            "STS form-body POST must be intercepted by the router"
        );
    }

    #[tokio::test]
    async fn non_sts_form_body_falls_through() {
        let router = test_router();
        let headers = http::HeaderMap::new();
        let req = RequestInfo::new(&http::Method::POST, "/", None, &headers, None)
            .with_form_body(Some("grant_type=client_credentials"));
        assert!(
            router.dispatch(&req).await.is_none(),
            "non-STS form body must fall through"
        );
    }
}
