# Cloudflare Workers

The CF Workers runtime deploys the proxy to Cloudflare's edge network. It compiles to WASM and runs in the Workers V8 environment.

## Limitations

> [!WARNING]
> - **S3 backends only** — Azure and GCS are not supported on WASM
> - **Static config only** — config is supplied inline via the `PROXY_CONFIG` var
> - **`SESSION_TOKEN_KEY` required** — Workers are stateless, so sealed tokens are the only way to persist temporary credentials

## Configuration

### `wrangler.toml`

The repository ships two Wrangler configs in `examples/cf-workers/`:

- **`wrangler.toml`** — for **local dev only**. Its buckets point at `http://localhost:9000` (the MinIO instance from Docker Compose).
- **`wrangler.deploy.toml`** — the production config used by CI. Treat this file as the source of truth for the full set of required bindings (rate limiters, Durable Object + migration, bandwidth quotas).

A minimal `PROXY_CONFIG` looks like this (note the TOML table-array form for buckets):

```toml
compatibility_date = "2024-11-11"
main = "build/worker/shim.mjs"
name = "multistore"

[build]
# worker-build is pinned to ^0.7 to match the pinned `worker` crate version.
command = "cargo install worker-build --version '^0.7' && worker-build --release"

[vars]
VIRTUAL_HOST_DOMAIN = "s3.example.com"

[vars.PROXY_CONFIG]

[[vars.PROXY_CONFIG.buckets]]
name = "public-data"
backend_type = "s3"
anonymous_access = true
allowed_roles = []

[vars.PROXY_CONFIG.buckets.backend_options]
bucket_name = "my-bucket"
endpoint = "https://s3.us-east-1.amazonaws.com"
region = "us-east-1"
```

Production deployments also require the rate-limit, Durable Object (with its `[[migrations]]` sqlite class), and bandwidth-quota bindings. Rather than hand-writing these, copy and adapt `examples/cf-workers/wrangler.deploy.toml`, which already includes:

- `[[ratelimits]]` for the `ANON_RATE_LIMITER` and `AUTH_RATE_LIMITER` limiters
- `[[durable_objects.bindings]]` binding `BANDWIDTH_METER` to the `BandwidthMeter` class, plus the `[[migrations]]` `new_sqlite_classes` entry
- `[vars.BANDWIDTH_QUOTAS]` per-bucket bandwidth limits

`PROXY_CONFIG` can be either:
- A JSON string (via `wrangler secret put PROXY_CONFIG`)
- A TOML table (via `[vars.PROXY_CONFIG]` in `wrangler.toml`, as shown above)

### Secrets

Set sensitive values as secrets:

```bash
wrangler secret put SESSION_TOKEN_KEY
wrangler secret put OIDC_PROVIDER_KEY
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PROXY_CONFIG` | Yes | JSON config (buckets, roles, credentials) |
| `VIRTUAL_HOST_DOMAIN` | No | Domain for virtual-hosted requests |
| `SESSION_TOKEN_KEY` | For STS | Base64-encoded 32-byte AES-256-GCM key |
| `OIDC_PROVIDER_KEY` | For OIDC backend auth | PEM-encoded RSA private key |
| `OIDC_PROVIDER_ISSUER` | For OIDC backend auth | Public URL for JWKS discovery |

## Building

```bash
# Check
cargo check -p multistore-cf-workers --target wasm32-unknown-unknown

# Build (via Wrangler)
cd examples/cf-workers
npx wrangler build
```

> [!WARNING]
> Always use `--target wasm32-unknown-unknown` when checking or building the CF Workers crate. It is excluded from the workspace `default-members` because WASM types won't compile on native targets.

## Development

```bash
cd examples/cf-workers
npx wrangler dev
```

This starts a local dev server on port `8787`.

## Deploying

The default `wrangler.toml` is a **local dev** config — its buckets point at `http://localhost:9000` (MinIO), so it is not suitable for production. Deploy with the production config (`wrangler.deploy.toml`) instead, mirroring how CI deploys (`.github/workflows/deploy.yml`):

```bash
npx wrangler deploy \
  --cwd examples/cf-workers \
  --config wrangler.deploy.toml
```

Deployment requires the `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` environment variables. After deploying, set the worker secrets:

```bash
npx wrangler secret put SESSION_TOKEN_KEY --cwd examples/cf-workers --config wrangler.deploy.toml
npx wrangler secret put OIDC_PROVIDER_KEY --cwd examples/cf-workers --config wrangler.deploy.toml
```
