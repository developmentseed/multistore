# Local Development

This guide walks through setting up a full local development environment with [RustFS](https://github.com/rustfs/rustfs), an S3-compatible server, as the backing object store. (MinIO no longer publishes public images.)

## Docker Compose

The project includes a `docker-compose.yaml` that starts RustFS and seeds it with example data:

```bash
docker compose up
```

This starts:
- **RustFS S3 API** at `http://localhost:9000`
- **RustFS Console** at `http://localhost:9001` (credentials: `minioadmin` / `minioadmin`)
- A seed job that creates `public-data` and `private-uploads` buckets with sample files

## Configuration Files

The two runtimes use different config formats:

### Workers Runtime — `examples/cf-workers/wrangler.toml`

The CF Workers runtime reads `PROXY_CONFIG` from the Wrangler configuration. The shipped `wrangler.toml` points the `public-data` and `private-uploads` buckets at `http://localhost:9000` (the RustFS instance seeded by Docker Compose), so it works against the local backend out of the box:

```bash
cd examples/cf-workers && npx wrangler dev
```

The Workers dev server runs on port `8787` by default. This is the recommended runtime for the local RustFS quickstart.

### Server Runtime — `examples/server/config.toml`

The server runtime reads a TOML config file, defaulting to `config.toml` in the working directory. The shipped `examples/server/config.toml` serves the `harvard-lil` and `cholmes` buckets from real AWS S3 (not the local RustFS buckets), so point `--config` at your own config to use a local backend:

```bash
cargo run -p multistore-server -- \
  --config examples/server/config.toml \
  --listen 0.0.0.0:8080
```

## Building

```bash
# Check/build default workspace members (excludes cf-workers)
cargo check
cargo build

# CF Workers must target wasm32
cargo check -p multistore-cf-workers --target wasm32-unknown-unknown

# Run tests
cargo test
```

## Environment Variables

For local development, these are optional but useful:

| Variable | Purpose | Example |
|----------|---------|---------|
| `SESSION_TOKEN_KEY` | AES-256-GCM key for sealed tokens | `openssl rand -base64 32` |
| `OIDC_PROVIDER_KEY` | RSA private key for OIDC backend auth | PEM file contents |
| `OIDC_PROVIDER_ISSUER` | Public URL for OIDC discovery | `http://localhost:8080` |
| `RUST_LOG` | Logging level | `multistore=debug` |

## Verifying the Setup

Once the Workers dev server is running, test both anonymous and authenticated access against the local RustFS buckets:

```bash
# Anonymous read (should return file contents)
curl http://localhost:8787/public-data/hello.txt

# Authenticated upload
AWS_ACCESS_KEY_ID=AKLOCAL0000000000001 \
AWS_SECRET_ACCESS_KEY="localdev/secret/key/00000000000000000000" \
aws s3 cp ./test.txt s3://private-uploads/test.txt \
    --endpoint-url http://localhost:8787

# List bucket contents
AWS_ACCESS_KEY_ID=AKLOCAL0000000000001 \
AWS_SECRET_ACCESS_KEY="localdev/secret/key/00000000000000000000" \
aws s3 ls s3://private-uploads/ \
    --endpoint-url http://localhost:8787

# Browse RustFS directly
open http://localhost:9001
```
