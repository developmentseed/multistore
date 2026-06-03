# Quick Start

The Multistore proxy is a multi-runtime S3 gateway that proxies requests to backend object stores. This guide gets you running locally in minutes.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Docker](https://docs.docker.com/get-docker/) (for local development with MinIO)

## Start the Backend

Use Docker Compose to start MinIO as a local object store:

```bash
docker compose up
```

This starts:
- MinIO API on port `9000`
- MinIO Console on port `9001` (user: `minioadmin`, password: `minioadmin`)
- A seed job that creates example buckets with test data

## Run the Proxy

The shipped Cloudflare Workers config (`examples/cf-workers/wrangler.toml`) wires the `public-data` and `private-uploads` buckets to the local MinIO instance started above, so it works out of the box:

```bash
cd examples/cf-workers && npx wrangler dev
```

The Workers dev server listens on port `8787`.

> The native server example (`examples/server/config.toml`) ships a different set of buckets pointed at real AWS S3, not the local MinIO buckets. See [Local Development](./local-development) for details on each runtime's config.

## Make Your First Request

```bash
# Anonymous read from a public bucket
curl http://localhost:8787/public-data/hello.txt

# Signed upload with the local dev credential
AWS_ACCESS_KEY_ID=AKLOCAL0000000000001 \
AWS_SECRET_ACCESS_KEY="localdev/secret/key/00000000000000000000" \
aws s3 cp ./myfile.txt s3://private-uploads/myfile.txt \
    --endpoint-url http://localhost:8787
```

## Next Steps

- [Local Development](./local-development) — Detailed dev environment setup
- [Configuration](/configuration/) — Configuring buckets, roles, and credentials
- [Authentication](/auth/) — Setting up auth flows
- [Deployment](/deployment/) — Deploying to production
