//! Rate limiting middleware using Cloudflare Workers Rate Limiting API.
//!
//! Uses two separate rate limiters: one for unauthenticated (anonymous)
//! requests keyed by source IP, and one for authenticated requests keyed
//! by access key ID.

use multistore::api::response::ErrorResponse;
use multistore::error::ProxyError;
use multistore::middleware::{Middleware, Next, RequestContext};
use multistore::route_handler::{HandlerAction, ProxyResponseBody, ProxyResult};
use multistore::types::ResolvedIdentity;

use bytes::Bytes;
use http::HeaderMap;

/// Rate limiting middleware backed by Cloudflare Workers rate limit bindings.
///
/// Selects the appropriate rate limiter based on the resolved identity:
/// - Anonymous requests use `anon_limiter`, keyed by source IP.
/// - Authenticated requests use `auth_limiter`, keyed by access key ID.
pub struct CfRateLimiter {
    anon_limiter: worker::RateLimiter,
    auth_limiter: worker::RateLimiter,
}

impl CfRateLimiter {
    pub fn new(anon_limiter: worker::RateLimiter, auth_limiter: worker::RateLimiter) -> Self {
        Self {
            anon_limiter,
            auth_limiter,
        }
    }
}

impl Middleware for CfRateLimiter {
    async fn handle<'a>(
        &'a self,
        ctx: RequestContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        let identity = ctx.identity().unwrap_or(&ResolvedIdentity::Anonymous);
        let (limiter, key) = match identity {
            ResolvedIdentity::Anonymous => {
                let key = match ctx.source_ip {
                    Some(ip) => ip.to_string(),
                    None => {
                        tracing::warn!("no source IP for anonymous request, using shared key");
                        "anonymous".to_string()
                    }
                };
                (&self.anon_limiter, key)
            }
            ResolvedIdentity::Authenticated(id) => (&self.auth_limiter, id.principal_name.clone()),
        };

        match limiter.limit(key.clone()).await {
            Ok(outcome) if outcome.success => {
                tracing::debug!(key = %key, "rate limit check passed");
                next.run(ctx).await
            }
            Ok(_) => {
                tracing::warn!(key = %key, "rate limited");
                let xml = ErrorResponse::slow_down(&ctx.request_id).to_xml();
                let mut headers = HeaderMap::new();
                headers.insert("content-type", "application/xml".parse().unwrap());
                Ok(HandlerAction::Response(ProxyResult {
                    status: 503,
                    headers,
                    body: ProxyResponseBody::Bytes(Bytes::from(xml)),
                }))
            }
            Err(err) => {
                // If the rate limiter fails, log and allow the request through
                // rather than blocking legitimate traffic.
                tracing::error!(key = %key, error = %err, "rate limiter error, allowing request");
                next.run(ctx).await
            }
        }
    }
}
