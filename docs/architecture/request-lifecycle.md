# Request Lifecycle

Every request flows through the `ProxyGateway`: first through the `Router` (which maps paths to handlers for STS, OIDC discovery, etc.), then into the two-phase proxy dispatch (resolve, then execute). The recommended entry point is `ProxyGateway::handle_request`, which returns a two-variant `GatewayResponse` for simple runtime integration.

## Overview

```mermaid
sequenceDiagram
    participant Client
    participant Runtime as Runtime<br/>(Server, Lambda, or Workers)
    participant Gateway as ProxyGateway
    participant Router as Router<br/>(STS, OIDC)
    participant BucketReg as BucketRegistry
    participant CredReg as CredentialRegistry
    participant Backend as Backend Store

    Client->>Runtime: HTTP request
    Runtime->>Gateway: handle_request(req_info, body, collect_body)
    Gateway->>Router: dispatch(req_info)
    alt Router matches (STS, OIDC discovery)
        Router-->>Gateway: Some(Response)
        Gateway-->>Runtime: GatewayResponse::Response
        Runtime-->>Client: Return response
    else No route matches
        Router-->>Gateway: None
        Gateway->>Gateway: Parse S3 operation
        Gateway->>CredReg: resolve_identity (SigV4 verification)
        CredReg-->>Gateway: ResolvedIdentity
        alt ListBuckets
            Gateway->>BucketReg: list_buckets(identity)
            BucketReg-->>Gateway: Vec<BucketEntry>
            Gateway-->>Runtime: GatewayResponse::Response (XML)
        else Bucket operation
            Gateway->>BucketReg: get_bucket(name, identity, operation)
            BucketReg-->>Gateway: ResolvedBucket (config + authz)
            Gateway->>Gateway: Dispatch operation
        end

        alt Forward (GET/HEAD/PUT/DELETE)
            Gateway-->>Runtime: GatewayResponse::Forward(fwd, body)
            Runtime->>Backend: Execute presigned URL (zero-copy streaming)
            Backend-->>Runtime: Stream response
            Runtime-->>Client: Stream response
        else Response (LIST, errors)
            Gateway-->>Runtime: GatewayResponse::Response
            Runtime-->>Client: Return response body
        else NeedsBody (multipart)
            Gateway->>Gateway: collect_body(body) → bytes
            Gateway->>Backend: Signed multipart request
            Backend-->>Gateway: Response
            Gateway-->>Runtime: GatewayResponse::Response
            Runtime-->>Client: Response
        end
    end
```

## Router

Before the proxy dispatch pipeline runs, the `Router` matches the request path against registered routes using `matchit`. Exact paths take priority over catch-all patterns, so OIDC discovery endpoints (`/.well-known/*`) are matched before the STS catch-all (`/{*path}`).

When a route matches, the router extracts path parameters from the pattern and populates `RequestInfo::params`. Handlers access parameters by name via `params.get("name")`.

Built-in route handlers:

- **`OidcRouterExt`** (`multistore-oidc-provider`) — Registers handlers for `/.well-known/openid-configuration` and `/.well-known/jwks.json`
- **`StsRouterExt`** (`multistore-sts`) — Registers a handler that intercepts `AssumeRoleWithWebIdentity` STS requests

### Method routing

Handlers implement the `RouteHandler` trait and override individual HTTP method handlers (`get`, `post`, `put`, `delete`, `head`) for method-specific behavior, or override `handle` directly for method-agnostic handlers:

```rust
use multistore::router::Router;

struct HealthCheck;

impl RouteHandler for HealthCheck {
    fn get<'a>(&'a self, _req: &'a RequestInfo<'a>) -> RouteHandlerFuture<'a> {
        Box::pin(async { Some(ProxyResult::json(200, r#"{"ok":true}"#)) })
    }
}

let router = Router::new()
    .route("/api/health", HealthCheck);
```

### Extension traits

Extension crates provide `Router` extension traits for one-call registration:

```rust
use multistore::router::Router;
use multistore_oidc_provider::route_handler::OidcRouterExt;
use multistore_sts::route_handler::StsRouterExt;

let router = Router::new()
    .with_oidc_discovery(issuer, signer)
    .with_sts(sts_creds, jwks_cache, token_key);

let gateway = ProxyGateway::new(backend, bucket_registry, cred_registry, domain)
    .with_credential_resolver(token_key)
    .with_backend_auth(oidc_auth)
    .with_router(router);
```

## Phase 1: Request Resolution

The `ProxyGateway` owns S3 request parsing, identity resolution, and bucket authorization:

1. **Parse the S3 operation** from the HTTP method, path, query, and headers
   - Path-style: `GET /bucket/key` → GetObject on `bucket` with key `key`
   - Virtual-hosted: `GET /key` with `Host: bucket.s3.example.com` → same operation
2. **Resolve identity** via the `CredentialRegistry` — verifies SigV4 signatures against stored or sealed credentials
3. **Resolve bucket** via the `BucketRegistry` — looks up the bucket config and authorizes the caller
4. **Dispatch** the operation based on type (forward, list, or multipart)

Custom `BucketRegistry` implementations can provide entirely different authorization logic, namespace mapping, or dynamic bucket configuration.

## Phase 2: Proxy Dispatch

The gateway takes the resolved bucket config and dispatches it based on the S3 operation type. When using `handle_request`, the three internal action types are collapsed into a two-variant `GatewayResponse`:

### `Forward(ForwardRequest)`

Used for: **GET, HEAD, PUT, DELETE**

The handler generates a presigned URL using the backend's `Signer` and returns it to the runtime with filtered headers. The runtime executes the presigned URL with its native HTTP client, streaming request and response bodies directly. The handler never touches the body data.

- Presigned URL TTL: 300 seconds
- Headers forwarded: `range`, `if-match`, `if-none-match`, `if-modified-since`, `if-unmodified-since`, `content-type`, `content-length`, `content-md5`, `content-encoding`, `content-disposition`, `cache-control`, `x-amz-content-sha256`

### `Response(ProxyResult)`

Used for: **LIST, errors, synthetic responses**

For LIST operations, the handler calls `list_paginated()` via the backend's `PaginatedListStore`, builds S3 `ListObjectsV2` XML from the results, and returns it as a complete response. If a `ListRewrite` is configured, key prefixes are transformed in the XML.

LIST supports backend-side pagination via `max-keys`, `continuation-token`, and `start-after` query parameters, fetching only one page per request.

### `NeedsBody(PendingRequest)` (internal)

Used for: **CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload**

Multipart operations need the request body (e.g., the XML body for `CompleteMultipartUpload`). When using `handle_request`, this is resolved internally — the gateway calls the `collect_body` closure provided by the runtime and returns the result as `GatewayResponse::Response`. Runtimes never see this variant.

For lower-level control, `ProxyGateway::handle` returns the raw three-variant `HandlerAction`, and runtimes call `handle_with_body()` themselves.

> [!WARNING]
> Multipart uploads are only supported for `backend_type = "s3"`. Non-S3 backends should use single PUT requests (object_store handles chunking internally).

## Response Header Forwarding

The proxy forwards only specific headers from the backend response to the client:

`content-type`, `content-length`, `content-range`, `etag`, `last-modified`, `accept-ranges`, `content-encoding`, `content-disposition`, `cache-control`, `x-amz-request-id`, `x-amz-version-id`, `location`

All other backend headers are filtered out.
