//! Path-based request router.
//!
//! The [`Router`] maps URL path patterns to [`RouteHandler`] implementations,
//! giving exact paths priority over catch-all patterns. Extension crates
//! register their routes via extension traits on `Router` (e.g. `OidcRouterExt`,
//! `StsRouterExt`), making integration a single chained call.
//!
//! Handlers implement [`RouteHandler::handle`] as an `async fn` and return
//! `Some(result)` to answer the request or `None` to fall through:
//!
//! ```rust,ignore
//! use multistore::router::Router;
//!
//! let router = Router::new()
//!     .route("/api/health", HealthCheck);
//! ```

use crate::route_handler::{ErasedRouteHandler, HandlerAction, Params, RequestInfo, RouteHandler};

/// Path-based request router.
///
/// Wraps [`matchit::Router`] to map URL path patterns to [`RouteHandler`]
/// implementations. Supports `matchit` path syntax: `/exact`,
/// `/prefix/{param}`, `/{*catch_all}`.
///
/// Exact paths are matched before parameterized/catch-all patterns, so
/// registering `/.well-known/openid-configuration` alongside `/{*path}`
/// will always route OIDC discovery before the catch-all.
pub struct Router {
    inner: matchit::Router<Box<dyn ErasedRouteHandler>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            inner: matchit::Router::new(),
        }
    }

    /// Register a handler for a path pattern.
    ///
    /// Supports matchit syntax: `/exact`, `/prefix/{param}`, `/{*catch_all}`.
    /// Panics if the path conflicts with an already-registered route.
    pub fn route(mut self, path: &str, handler: impl RouteHandler + 'static) -> Self {
        self.inner
            .insert(path, Box::new(handler))
            .expect("conflicting route");
        self
    }

    /// Try to match a path and invoke the matched handler.
    ///
    /// On match, the handler receives a [`RequestInfo`] with populated
    /// [`Params`] extracted from the path pattern.
    ///
    /// Returns `Some(action)` if a route matched and the handler produced an
    /// action. Returns `None` if no route matched or the handler declined
    /// (returned `None`).
    pub async fn dispatch(&self, req: &RequestInfo<'_>) -> Option<HandlerAction> {
        let matched = self.inner.at(req.path).ok()?;
        let params = Params::from_matchit(&matched.params);
        let req_with_params = RequestInfo {
            params,
            method: req.method,
            path: req.path,
            query: req.query,
            headers: req.headers,
            source_ip: req.source_ip,
            signing_path: req.signing_path,
            signing_query: req.signing_query,
            copy_source: req.copy_source,
            form_body: req.form_body,
        };
        matched
            .value
            .handle(&req_with_params)
            .await
            .map(HandlerAction::Response)
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_handler::ProxyResult;

    /// A handler written the way integrators will write one: a plain
    /// `async fn`, no manual boxing.
    struct HealthCheck;

    impl RouteHandler for HealthCheck {
        async fn handle<'a>(&'a self, req: &'a RequestInfo<'a>) -> Option<ProxyResult> {
            (req.method == http::Method::GET).then(|| ProxyResult::json(200, r#"{"ok":true}"#))
        }
    }

    #[test]
    fn async_fn_handler_dispatches_and_falls_through() {
        let router = Router::new().route("/health", HealthCheck);
        let headers = http::HeaderMap::new();
        let get = RequestInfo::new(&http::Method::GET, "/health", None, &headers, None);
        let post = RequestInfo::new(&http::Method::POST, "/health", None, &headers, None);
        let other = RequestInfo::new(&http::Method::GET, "/nope", None, &headers, None);

        futures::executor::block_on(async {
            assert!(matches!(
                router.dispatch(&get).await,
                Some(HandlerAction::Response(r)) if r.status == 200
            ));
            assert!(router.dispatch(&post).await.is_none(), "handler declined");
            assert!(router.dispatch(&other).await.is_none(), "no route matched");
        });
    }

    /// `matchit`'s `/{*path}` catch-all does NOT match the bare root `/`.
    /// Route handlers that need to match `/` must register an explicit `/` route.
    #[test]
    fn matchit_catchall_does_not_match_root() {
        let mut router = matchit::Router::<&str>::new();
        router.insert("/{*path}", "handler").unwrap();
        assert!(router.at("/").is_err());
    }

    #[test]
    fn explicit_root_route_matches() {
        let mut router = matchit::Router::<&str>::new();
        router.insert("/", "root").unwrap();
        assert!(router.at("/").is_ok());
    }
}
