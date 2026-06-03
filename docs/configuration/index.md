# Configuration

The proxy configuration defines three things:

1. **[Buckets](./buckets)** — Virtual buckets that map client-visible names to backend object stores
2. **[Roles](./roles)** — Trust policies for OIDC token exchange via `AssumeRoleWithWebIdentity`
3. **[Credentials](./credentials)** — Long-lived access keys for service accounts and internal tools

```mermaid
flowchart TD
    Config["Proxy Configuration"]
    Config --> Buckets["Buckets<br>(virtual names → backends)"]
    Config --> Roles["Roles<br>(OIDC trust policies)"]
    Config --> Creds["Credentials<br>(static access keys)"]

    Roles -- "allowed_scopes" --> Buckets
    Creds -- "allowed_scopes" --> Buckets
```

## Config Format

The server runtime uses TOML:

```toml
[[buckets]]
name = "public-data"
backend_type = "s3"
anonymous_access = true

[buckets.backend_options]
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket_name = "my-public-assets"
region = "us-east-1"
```

The CF Workers runtime uses JSON (as an environment variable or `wrangler.toml` object):

```json
{
  "buckets": [{
    "name": "public-data",
    "backend_type": "s3",
    "anonymous_access": true,
    "backend_options": {
      "endpoint": "https://s3.us-east-1.amazonaws.com",
      "bucket_name": "my-public-assets",
      "region": "us-east-1"
    }
  }]
}
```

## Top-Level Keys

Alongside the `buckets`, `roles`, and `credentials` arrays, the static file config accepts two optional top-level keys that control the owner identity reported in `ListBuckets` (`ListAllMyBucketsResult`) responses:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `owner_id` | string | No | Owner ID returned in `ListBuckets` responses. Defaults to `multistore-proxy` when omitted. |
| `owner_display_name` | string | No | Owner display name returned in `ListBuckets` responses. Defaults to `multistore-proxy` when omitted. |

```toml
owner_id = "my-org"
owner_display_name = "My Organization"

[[buckets]]
name = "public-data"
# ...
```

## Config Providers

The proxy can load configuration from multiple backends. See [Config Providers](./providers/) for details.

| Provider | Status | Use Case |
|----------|--------|----------|
| [Static File](./providers/static-file) | Built-in (always available) | Simple deployments, baked-in config |
| [HTTP API](./providers/http) | Planned — not yet implemented | Centralized config service |
| [DynamoDB](./providers/dynamodb) | Planned — not yet implemented | AWS-native infrastructure |
| [PostgreSQL](./providers/postgres) | Planned — not yet implemented | Database-backed config |

The static file provider is the only config provider in the current release. The HTTP, DynamoDB, and PostgreSQL providers are planned features; there are no `config-http`/`config-dynamodb`/`config-postgres` feature flags today.

## Full Example

See the [annotated config example](/reference/config-example) for a complete configuration file with all options documented.
