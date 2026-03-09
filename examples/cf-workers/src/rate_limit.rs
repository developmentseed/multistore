//! Rate limiting middleware using Cloudflare Workers Rate Limiting API.
//!
//! Uses two separate rate limiters: one for unauthenticated (anonymous)
//! requests keyed by source IP, and one for authenticated requests keyed
//! by access key ID.

use multistore::error::ProxyError;
use multistore::middleware::{DispatchContext, Middleware, Next};
use multistore::route_handler::{HandlerAction, ProxyResponseBody, ProxyResult};
use multistore::types::ResolvedIdentity;

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
        ctx: DispatchContext<'a>,
        next: Next<'a>,
    ) -> Result<HandlerAction, ProxyError> {
        let (limiter, key) = match ctx.identity {
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
            ResolvedIdentity::LongLived { credential } => {
                (&self.auth_limiter, credential.principal_name.clone())
            }
            ResolvedIdentity::Temporary { credentials } => {
                (&self.auth_limiter, credentials.source_identity.clone())
            }
        };

        match limiter.limit(key.clone()).await {
            Ok(outcome) if outcome.success => {
                tracing::debug!(key = %key, "rate limit check passed");
                next.run(ctx).await
            }
            Ok(_) => {
                tracing::warn!(key = %key, "rate limited");
                Ok(HandlerAction::Response(ProxyResult {
                    status: 429,
                    headers: HeaderMap::new(),
                    body: ProxyResponseBody::Bytes(
                        "Rate limit exceeded. Please try again later.".into(),
                    ),
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
