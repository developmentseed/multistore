//! Path-based request router.
//!
//! The [`Router`] maps URL path patterns to [`RouteHandler`] implementations,
//! giving exact paths priority over catch-all patterns. Extension crates
//! register their routes via extension traits on `Router` (e.g. `OidcRouterExt`,
//! `StsRouterExt`), making integration a single chained call.
//!
//! Handlers implement `RouteHandler` and override individual HTTP method
//! handlers (`get`, `post`, etc.) or `handle` directly:
//!
//! ```rust,ignore
//! use multistore::router::Router;
//!
//! let router = Router::new()
//!     .route("/api/health", HealthCheck);
//! ```

use crate::route_handler::{HandlerAction, Params, RequestInfo, RouteHandler};

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
    inner: matchit::Router<Box<dyn RouteHandler>>,
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
