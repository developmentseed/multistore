# multistore-backend-federation

Outbound credential federation for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway. The runtime-agnostic *client* side of AWS STS `AssumeRoleWithWebIdentity`: the proxy presents its own OIDC identity to a **backend cloud**, assumes a role there, and signs backend requests with the temporary credentials — so the operator never holds long-lived backend keys.

It is the symmetric counterpart to [`multistore-sts`](../sts), which is the inbound `AssumeRoleWithWebIdentity` **server** (minting proxy credentials for callers).

```
                 inbound                          outbound
  caller ──OIDC──▶ multistore-sts          multistore-backend-federation ──OIDC──▶ backend cloud STS
        ◀─proxy creds─ (server: mint)       (client: build req / parse resp) ◀─backend creds─
```

## How It Works

```
proxy's OIDC identity (multistore-oidc-provider mints + signs the JWT)
    │
    │  self-signed JWT (web identity token)
    ▼
┌──────────────────────────────────────┐
│  multistore-backend-federation        │
│                                       │
│  1. build AssumeRoleWithWebIdentity   │  ← request URL + form body / pairs
│     request (this crate)              │
│  2. caller POSTs it to backend STS    │  ← transport owned by the caller
│  3. parse_response(xml)               │  ← typed creds or typed FederationError::Sts
│  4. FederatedCredentials::apply_to    │  ← inject into BucketConfig.backend_options
└──────────────────────────────────────┘
    │
    │  temporary backend AccessKeyId + SecretAccessKey + SessionToken
    ▼
multistore S3 backend signs requests to the private bucket
```

This crate is **mechanism only**: it owns the STS request/response shapes and the `BucketConfig` injection. It does *not* mint the JWT, perform HTTP, cache, or wire middleware — that orchestration lives in [`multistore-oidc-provider`](../oidc-provider), which delegates its AWS exchange to this crate.

## Relationship to the other auth crates

| crate | direction | role |
|---|---|---|
| `multistore-sts` | inbound | server: validate caller OIDC token, mint `TemporaryCredentials` |
| `multistore-oidc-provider` | outbound | mint the proxy's own JWT (sign/JWKS/discovery) + cache + middleware |
| `multistore-backend-federation` | outbound | client: build/parse backend STS exchange, inject `FederatedCredentials` |

## Bring your own token

Because the crate only depends on `multistore` (core) and a few wire libraries — no RSA/JWKS machinery — a caller that already holds a web-identity token (an external IdP, a workload-identity assertion, a pre-minted JWT) can use it standalone to exchange that token for backend credentials, without pulling in the full OIDC provider.
