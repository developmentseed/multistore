# Roles

Roles define trust policies for OIDC token exchange via `AssumeRoleWithWebIdentity`. Each role specifies which identity providers to trust, what subject constraints to enforce, and what access scopes to grant.

## Configuration

```toml
[[roles]]
role_id = "github-actions-deployer"
name = "GitHub Actions Deploy Role"
trusted_oidc_issuers = ["https://token.actions.githubusercontent.com"]
required_audience = "sts.s3proxy.example.com"
subject_conditions = [
    "repo:myorg/myapp:ref:refs/heads/main",
    "repo:myorg/infrastructure:*",
]
max_session_duration_secs = 3600

[[roles.allowed_scopes]]
bucket = "deploy-bundles"
prefixes = []
actions = ["get_object", "head_object", "put_object"]

[[roles.allowed_scopes]]
bucket = "ml-artifacts"
prefixes = ["models/", "datasets/"]
actions = ["get_object", "head_object"]
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `role_id` | string | Yes | Identifier used as the `RoleArn` in STS requests |
| `name` | string | Yes | Human-readable display name |
| `trusted_oidc_issuers` | string[] | Validated as required | OIDC provider URLs whose tokens are accepted. Deserializes fine when absent, but config validation rejects a role with no issuers (it could never accept a token). |
| `required_audience` | string | No | If set, the token's `aud` claim must match |
| `subject_conditions` | string[] | No | Glob patterns matched against the `sub` claim. When omitted or empty, the subject check is skipped entirely and all subjects match. |
| `max_session_duration_secs` | integer | Yes | Maximum session lifetime granted by this role |
| `allowed_scopes` | AccessScope[] | Yes | Buckets, prefixes, and actions granted |

## Trust Policy Evaluation

When a client calls `AssumeRoleWithWebIdentity`, the proxy evaluates the JWT against the role's trust policy in this order:

1. **Issuer** — The JWT's `iss` claim must match one of `trusted_oidc_issuers`
2. **Algorithm** — Only RS256 is supported
3. **Signature** — Verified against the issuer's JWKS (fetched and cached)
4. **Audience** — If `required_audience` is set, the JWT's `aud` claim must match
5. **Subject** — If `subject_conditions` is non-empty, the JWT's `sub` claim must match at least one pattern. If it is empty (or omitted), the subject check is skipped and all subjects pass.

If any check fails, the STS request returns an error.

## Subject Conditions

Subject conditions use glob-style matching where `*` matches any sequence of characters:

```toml
subject_conditions = [
    "repo:myorg/myapp:ref:refs/heads/main",      # Exact match
    "repo:myorg/myapp:ref:refs/heads/release/*",  # Prefix match
    "repo:myorg/*",                                # Any repo in the org
    "*",                                           # Any subject
]
```

The `sub` claim only needs to match one of the patterns. If `subject_conditions` is omitted or left empty, the subject check is skipped entirely and every subject is accepted.

## Session Duration

`max_session_duration_secs` is the maximum session lifetime this role grants. At mint time, the caller's requested `DurationSeconds` is clamped into the range `[900, max_session_duration_secs]` — the 900-second floor is a clamp applied to the requested session length (matching AWS's STS minimum), not a validated minimum on the field itself. If no duration is requested, 3600s is used (subject to the same clamp).

## Access Scopes

Each scope grants access to a specific bucket with optional prefix and action restrictions:

```toml
[[roles.allowed_scopes]]
bucket = "deploy-bundles"
prefixes = ["releases/", "staging/"]
actions = ["get_object", "head_object", "put_object"]
```

| Field | Type | Description |
|-------|------|-------------|
| `bucket` | string | Virtual bucket name (or template variable) |
| `prefixes` | string[] | Allowed key prefixes (empty = full bucket access) |
| `actions` | string[] | Allowed S3 operations |

### Available Actions

| Action | S3 Operation |
|--------|-------------|
| `get_object` | GET (download) |
| `head_object` | HEAD (metadata) |
| `put_object` | PUT (upload) |
| `delete_object` | DELETE |
| `list_bucket` | LIST (list objects) |
| `create_multipart_upload` | POST (initiate multipart) |
| `upload_part` | PUT with partNumber (upload part) |
| `complete_multipart_upload` | POST with uploadId (complete multipart) |
| `abort_multipart_upload` | DELETE with uploadId (abort multipart) |

### Prefix Matching

Prefix matching follows these rules:

- If the prefix ends with `/` or is empty: the key must start with the prefix
- Otherwise: the key must equal the prefix exactly, or start with the prefix followed by `/`

> [!IMPORTANT]
> A prefix without a trailing `/` must match exactly or be followed by `/`. This prevents `data` from matching `data-private/secret.txt`. Use `data/` to restrict to that directory.

## Template Variables

Scope `bucket` and `prefixes` values support `{claim_name}` template variables that are resolved from the JWT claims at credential mint time:

```toml
[[roles]]
role_id = "user-role"
trusted_oidc_issuers = ["https://auth.example.com"]
subject_conditions = ["*"]
max_session_duration_secs = 3600

# Each user gets access to a bucket matching their subject claim
[[roles.allowed_scopes]]
bucket = "{sub}"
prefixes = []
actions = ["get_object", "head_object", "put_object", "list_bucket"]
```

A user with `sub = "alice"` receives credentials scoped to `bucket = "alice"`. Any string claim from the JWT can be referenced — `{email}`, `{org}`, etc.

Missing or non-string claims resolve to an empty string, which safely fails authorization.

### Examples

**Per-user bucket access:**
```toml
bucket = "{sub}"
```

**Organization-scoped prefix:**
```toml
bucket = "shared-data"
prefixes = ["{org}/"]
```

**Read-only access to all buckets:**
```toml
bucket = "*"
prefixes = []
actions = ["get_object", "head_object", "list_bucket"]
```
