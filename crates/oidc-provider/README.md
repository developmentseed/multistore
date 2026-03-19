# multistore-oidc-provider

OIDC identity provider and backend credential exchange for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Enables the proxy to act as its own OpenID Connect provider — signing JWTs, serving discovery/JWKS endpoints, and exchanging tokens with cloud providers for temporary backend credentials.

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

This allows multistore to authenticate to cloud storage backends using federated identity rather than long-lived keys.

## Feature Flags

- `azure` — Azure AD token exchange
- `gcp` — GCP workload identity federation
