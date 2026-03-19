# multistore-oidc-provider

OIDC identity provider and backend credential exchange for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Enables the proxy to act as its own OpenID Connect provider — signing JWTs, serving JWKS and discovery documents, and exchanging tokens with cloud providers for temporary backend credentials. This allows multistore to authenticate to cloud storage backends (AWS, Azure, GCP) using federated identity rather than long-lived keys.

## How It Works

```
Client request
    │
    ▼
┌──────────────────────────────┐
│  AwsBackendAuth middleware   │
│                              │
│  1. Check bucket auth_type   │
│  2. Mint JWT (RS256)         │
│  3. Exchange with cloud STS  │
│  4. Cache credentials        │
│  5. Inject into bucket config│
└──────────────────────────────┘
    │
    ▼
Backend request with temporary credentials
```

## Key Types

**`OidcCredentialProvider<H>`** — main provider that combines JWT signing, credential exchange, and caching. Generic over `HttpExchange` for runtime portability.

**`JwtSigner`** — signs JWTs using RS256 with a PKCS#8 private key. Produces standard claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`) with configurable TTL and extra claims.

**`AwsBackendAuth<H>`** — `Middleware` implementation that intercepts requests to OIDC-configured buckets, exchanges a JWT for cloud credentials, and injects them into the bucket config before dispatch.

**`CredentialExchange<H>`** — trait for cloud-specific token exchange:
- `AwsExchange` — `AssumeRoleWithWebIdentity` via AWS STS
- `AzureExchange` — OAuth 2.0 client credentials with JWT bearer (feature: `azure`)
- `GcpExchange` — workload identity federation + service account impersonation (feature: `gcp`)

## Discovery Endpoints

Register OIDC discovery routes on the gateway:

```rust
use multistore_oidc_provider::route_handler::OidcRouterExt;

let gateway = gateway.with_oidc_discovery(&issuer, &signer);
// Serves /.well-known/openid-configuration and /.well-known/jwks.json
```

## Feature Flags

- `azure` — Azure AD token exchange
- `gcp` — GCP workload identity federation
