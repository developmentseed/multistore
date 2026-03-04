# Crate Layout

The project is organized as a Cargo workspace with libraries (traits and logic) and example runtimes (executable targets).

```
crates/
├── core/  (multistore)                 # Runtime-agnostic: traits, S3 parsing, SigV4, config
├── sts/   (multistore-sts)             # OIDC/STS token exchange (AssumeRoleWithWebIdentity)
└── oidc-provider/                      # Outbound OIDC provider (JWT signing, JWKS, exchange)

examples/
├── server/ (multistore-server)         # Tokio/Hyper for container deployments
└── cf-workers/ (multistore-cf-workers) # Cloudflare Workers for edge deployments
```

## Crate Responsibilities

### `multistore`

The runtime-agnostic core. Contains:
- `ProxyHandler` — Two-phase request handler (`resolve_request()` → `HandlerAction`)
- `RequestResolver` and `DefaultResolver` — Request parsing, SigV4 auth, authorization
- `ConfigProvider` trait and implementations (static file, HTTP, DynamoDB, Postgres)
- `ProxyBackend` trait — Runtime abstraction for store/signer/raw HTTP
- S3 request parsing, XML response building, list prefix rewriting
- SigV4 signature verification
- Sealed session token encryption/decryption
- Type definitions (`BucketConfig`, `RoleConfig`, `AccessScope`, etc.)

**Feature flags:**
- `config-http` — HTTP API config provider
- `config-dynamodb` — DynamoDB config provider
- `config-postgres` — PostgreSQL config provider
- `azure` — Azure Blob Storage support
- `gcp` — Google Cloud Storage support

### `multistore-sts`

OIDC token exchange implementing `AssumeRoleWithWebIdentity`:
- JWT decoding and validation (RS256)
- JWKS fetching and caching
- Trust policy evaluation (issuer, audience, subject conditions)
- Temporary credential minting with scope template variables

### `multistore-oidc-provider`

Outbound OIDC identity provider for backend authentication:
- RSA JWT signing (`JwtSigner`)
- JWKS endpoint serving
- OpenID Connect discovery document
- AWS credential exchange (`AwsOidcBackendAuth`)
- Credential caching

### `multistore-server`

The native server runtime (in `examples/server/`):
- Tokio/Hyper HTTP server
- `ServerBackend` implementing `ProxyBackend` with reqwest
- Streaming via hyper `Incoming` bodies and reqwest `bytes_stream()`
- CLI argument parsing (`--config`, `--listen`, `--domain`, `--sts-config`)

### `multistore-cf-workers`

The Cloudflare Workers WASM runtime (in `examples/cf-workers/`):
- `WorkerBackend` implementing `ProxyBackend` with `web_sys::fetch`
- `FetchConnector` bridging `object_store` HTTP to Workers Fetch API
- JS `ReadableStream` passthrough for zero-copy streaming
- Config loading from env vars (`PROXY_CONFIG`)

> [!WARNING]
> This crate is excluded from the workspace `default-members` because WASM types are `!Send` and won't compile on native targets. Always build with `--target wasm32-unknown-unknown`.

## Dependency Flow

```mermaid
flowchart TD
    core["multistore"]
    sts["multistore-sts"]
    oidc["multistore-oidc-provider"]
    server["multistore-server"]
    workers["multistore-cf-workers"]

    server --> core
    server --> sts
    server --> oidc
    workers --> core
    workers --> sts
    workers --> oidc
    sts --> core
    oidc --> core
```

Libraries define trait abstractions. Runtimes implement `ProxyBackend` with platform-native primitives and wire everything together.
