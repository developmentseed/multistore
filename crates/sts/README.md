# multistore-sts

STS credential minting for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway. Implements `AssumeRoleWithWebIdentity`, allowing workloads like GitHub Actions to exchange OIDC JWTs for temporary, scoped S3 credentials.

## How It Works

```
OIDC Provider (e.g. GitHub Actions)
    │
    │  JWT (signed by provider)
    ▼
┌─────────────────────────────┐
│  multistore-sts             │
│                             │
│  1. Fetch JWKS from issuer  │
│  2. Verify JWT signature    │
│  3. Check trust policy      │
│  4. Mint temporary creds    │
└─────────────────────────────┘
    │
    │  AccessKeyId + SecretAccessKey + SessionToken
    ▼
Client signs S3 requests with temp creds
```

## Trust Policies

Roles define who can assume them:

- **`trusted_oidc_issuers`** — accepted OIDC providers (e.g., `https://token.actions.githubusercontent.com`)
- **`required_audiences`** — accepted `aud` claim values (string or list); a token passes if its `aud` matches any. Empty/omitted accepts no token. Legacy `required_audience` (single string) still accepted.
- **`subject_conditions`** — glob patterns for the `sub` claim (e.g., `repo:myorg/*`). Empty accepts no subject; `"*"` accepts any.
- **`allow_missing_exp_from`** — issuers whose tokens may omit `exp` because the host tracks their validity; every other issuer's tokens must carry it
- **`allowed_scopes`** — buckets, prefixes, and actions the minted credentials grant
