# Server Runtime

The server runtime uses Tokio and Hyper to run as a native HTTP server. It supports the S3 backend by default, with optional Azure and GCS backends behind cargo features.

## Building

```bash
# Default build (S3 backend)
cargo build --release -p multistore-server

# With Azure and/or GCS backends
cargo build --release -p multistore-server \
  --features multistore/azure \
  --features multistore/gcp
```

The binary is located at `target/release/multistore-server`.

## Running

```bash
./target/release/multistore-server \
  --config config.toml \
  --listen 0.0.0.0:8080
```

### CLI Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `config.toml` | Path to the TOML config file |
| `--listen` | `0.0.0.0:8080` | Address and port to listen on |
| `--domain` | (none) | Domain for virtual-hosted-style requests (e.g., `s3.example.com`) |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SESSION_TOKEN_KEY` | For STS | Base64-encoded 32-byte AES-256-GCM key for sealed tokens |
| `OIDC_PROVIDER_KEY` | For OIDC backend auth | PEM-encoded RSA private key |
| `OIDC_PROVIDER_ISSUER` | For OIDC backend auth | Publicly reachable URL for JWKS discovery |
| `RUST_LOG` | No | Logging level (default: `multistore=info`) |

Generate a session token key:

```bash
export SESSION_TOKEN_KEY=$(openssl rand -base64 32)
```

## Docker

> [!NOTE]
> The repository does not currently ship a `Dockerfile`. The snippet below is illustrative — you must supply your own image that builds and runs the `multistore-server` binary. Because the binary defaults `--config` to `./config.toml`, pass `--config` explicitly to point at the mounted config path.

```bash
# Run (assuming an image named `multistore-proxy` that you have built)
docker run \
  -v ./config.toml:/etc/multistore/config.toml \
  -p 8080:8080 \
  -e SESSION_TOKEN_KEY="$SESSION_TOKEN_KEY" \
  multistore-proxy \
  --config /etc/multistore/config.toml
```

## Config Caching

The server binary wraps the config provider with `CachedProvider` (60-second TTL). With a dynamic, network-backed config provider, changes would be picked up within 60 seconds without restarting the proxy.

The server currently ships only the static file provider, so config changes require a restart.

## Virtual-Hosted Style

To support virtual-hosted-style requests (`bucket.s3.example.com/key`), use the `--domain` flag:

```bash
./multistore-server --config config.toml --domain s3.example.com
```

Configure DNS so that `*.s3.example.com` resolves to the proxy. The proxy extracts the bucket name from the `Host` header.

Without `--domain`, only path-style requests are supported (`/bucket/key`).
