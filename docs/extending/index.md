# Extending the Proxy

The proxy is designed for customization through several trait boundaries. Each controls a different aspect of the proxy's behavior.

| Trait | Controls | Default Implementation |
|-------|----------|----------------------|
| [Router / RouteHandler](../architecture/request-lifecycle#router) | Path-based pre-dispatch request interception | `StsRouterExt`, `OidcRouterExt` |
| [Middleware](../architecture/request-lifecycle#phase-2-proxy-dispatch) | Post-auth dispatch interception and post-dispatch observation | `MeteringMiddleware` (`multistore-metering`) |
| [Forwarder](../architecture/request-lifecycle#forwardforwardresponses) | Runtime-provided HTTP transport for backend forwarding | `ServerForwarder`, `WorkerForwarder`, `LambdaForwarder` |
| [BucketRegistry](./custom-resolver) | Bucket lookup, authorization, and listing | `StaticProvider` (static file config) |
| [CredentialRegistry](./custom-provider) | Credential and role storage | `StaticProvider` (static file config) |
| [ProxyBackend](./custom-backend) | How the runtime interacts with backends | `ServerBackend`, `WorkerBackend` |

## When to Customize What

**Custom Route Handler** — You want to intercept requests before the proxy pipeline (e.g., health checks, metrics endpoints, custom authentication flows). Implement the `RouteHandler` trait on a struct and register it via `router.route(path, handler)`. Override individual HTTP method handlers (`get`, `post`, etc.) for method-specific behavior, or override `handle` directly for method-agnostic handlers. Handlers receive path parameters via `req.params.get("name")` when using parameterized routes like `/api/items/{id}`.

**Custom Middleware** — You want to intercept requests after identity resolution (e.g., rate limiting, logging, usage metering). Implement the `Middleware` trait with a `handle` method for pre-dispatch logic and optionally `after_dispatch` for post-response observation. Register via `gateway.with_middleware(my_middleware)`. See `multistore-metering` for an example.

**Custom Forwarder** — You're deploying to a new runtime and need to provide an HTTP client for backend forwarding. Implement the `Forwarder` trait with your runtime's native HTTP client. The response body type is an associated type, allowing zero-copy streaming (e.g., `web_sys::Response` on CF Workers).

**Custom Bucket Registry** — Your namespace mapping needs identity-aware authorization, external API calls for bucket lookup, or a different bucket listing strategy.

**Custom Credential Registry** — You want to store credentials/roles in a backend not already supported (e.g., etcd, Redis, Consul), or you need to derive them from another source.

**Custom Backend** — You're deploying to a runtime that's neither a standard server nor Cloudflare Workers (e.g., AWS Lambda, Deno Deploy), or you need a different HTTP client.
