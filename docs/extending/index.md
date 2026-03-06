# Extending the Proxy

The proxy is designed for customization through four trait boundaries. Each controls a different aspect of the proxy's behavior.

| Trait | Controls | Default Implementation |
|-------|----------|----------------------|
| [RouteHandler](../architecture/request-lifecycle#route-handlers) | Pre-dispatch request interception | `StsRouteHandler`, `OidcDiscoveryRouteHandler` |
| [BucketRegistry](./custom-resolver) | Bucket lookup, authorization, and listing | `StaticProvider` (static file config) |
| [CredentialRegistry](./custom-provider) | Credential and role storage | `StaticProvider` (static file config) |
| [ProxyBackend](./custom-backend) | How the runtime interacts with backends | `ServerBackend`, `WorkerBackend` |

## When to Customize What

**Custom Route Handler** — You want to intercept requests before the proxy pipeline (e.g., health checks, metrics endpoints, custom authentication flows). Implement the `RouteHandler` trait and register it via `gateway.with_route_handler(handler)`.

**Custom Bucket Registry** — Your namespace mapping needs identity-aware authorization, external API calls for bucket lookup, or a different bucket listing strategy.

**Custom Credential Registry** — You want to store credentials/roles in a backend not already supported (e.g., etcd, Redis, Consul), or you need to derive them from another source.

**Custom Backend** — You're deploying to a runtime that's neither a standard server nor Cloudflare Workers (e.g., AWS Lambda, Deno Deploy), or you need a different HTTP client.
