# Extending the Proxy

The proxy is designed for customization through four trait boundaries. Each controls a different aspect of the proxy's behavior.

| Trait | Controls | Default Implementation |
|-------|----------|----------------------|
| [RouteHandler](../architecture/request-lifecycle#route-handlers) | Pre-dispatch request interception | `StsRouteHandler`, `OidcDiscoveryRouteHandler` |
| [RequestResolver](./custom-resolver) | How requests are parsed, authenticated, and authorized | `DefaultResolver` (standard S3 proxy behavior) |
| [ConfigProvider](./custom-provider) | Where configuration comes from | Static file, HTTP, DynamoDB, Postgres |
| [ProxyBackend](./custom-backend) | How the runtime interacts with backends | `ServerBackend`, `WorkerBackend` |

## When to Customize What

**Custom Route Handler** — You want to intercept requests before the proxy pipeline (e.g., health checks, metrics endpoints, custom authentication flows). Implement the `RouteHandler` trait and register it via `gateway.with_route_handler(handler)`.

**Custom Resolver** — Your URL namespace doesn't map to `/{bucket}/{key}`, or you need external authorization (e.g., an API call), or you want different authentication logic.

**Custom Config Provider** — You want to store config in a backend not already supported (e.g., etcd, Redis, Consul), or you need to derive config from another source.

**Custom Backend** — You're deploying to a runtime that's neither a standard server nor Cloudflare Workers (e.g., AWS Lambda, Deno Deploy), or you need a different HTTP client.
