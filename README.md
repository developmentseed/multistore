# Multistore

A set of Rust crates for building multi-runtime S3 gateway proxies. Multistore provides the components — S3 request parsing, SigV4 authentication, backend resolution, configuration, and middleware — to assemble a proxy that sits between S3-compatible clients and backend object stores. Combine them into a native Tokio/Hyper server, a Cloudflare Worker at the edge, or your own custom runtime.

> [!WARNING]
> This project is in early stages and should be considered experimental. APIs and interfaces may change significantly between versions.

## Features

- **Unified interface** — Single stable URL per dataset regardless of backend provider. Backend migrations are invisible to data consumers.
- **Native S3 compatibility** — Works with aws-cli, boto3, DuckDB, obstore, GDAL, or any S3-compatible client. Just set the endpoint URL.
- **Flexible authentication** — Anonymous access, long-lived access keys, or OIDC/STS token exchange for temporary credentials.
- **Multi-runtime** — Same core logic deploys as a native server in containers or as a Cloudflare Worker at the edge.
- **Zero-copy streaming** — Presigned URLs enable direct streaming between clients and backends without buffering.
- **Extensible** — Pluggable traits for request resolution, configuration, and backend I/O.

## Crate Layout

```
crates/
├── core/              (multistore)                # Runtime-agnostic: traits, S3 parsing, SigV4, registries
├── metering/          (multistore-metering)       # Usage metering and quota enforcement middleware
├── sts/               (multistore-sts)            # OIDC/STS token exchange
├── oidc-provider/     (multistore-oidc-provider)  # Outbound OIDC provider
├── static-config/     (multistore-static-config)  # Static config provider
├── path-mapping/      (multistore-path-mapping)   # Path mapping utilities
└── cf-workers/        (multistore-cf-workers)     # Cloudflare Workers runtime (WASM)

examples/
├── server/            (multistore-server)         # Tokio/Hyper native server
├── lambda/            (multistore-lambda)         # AWS Lambda runtime
└── cf-workers/        (multistore-cf-workers)     # Cloudflare Workers
```

## Getting Started

See the [full documentation](https://developmentseed.org/multistore/getting-started/) for configuration, deployment, and usage guides.

## Development

```bash
# Format
cargo fmt

# Lint
cargo clippy --fix --allow-dirty --allow-staged

# Check (native)
cargo check

# Check (WASM)
cargo check -p multistore-cf-workers --target wasm32-unknown-unknown
```

## License

[MIT](LICENSE)
