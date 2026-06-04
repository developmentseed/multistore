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

The workspace is split into reusable **libraries** (traits and logic) and example **runtimes** (executable targets). Each crate name links to its API documentation on [docs.rs](https://docs.rs).

### Libraries

| Crate | Path | Description |
| ----- | ---- | ----------- |
| [`multistore`](https://docs.rs/multistore) | [`crates/core/`](crates/core) | Runtime-agnostic core: traits, S3 parsing, SigV4, registries |
| [`multistore-metering`](https://docs.rs/multistore-metering) | [`crates/metering/`](crates/metering) | Usage metering and quota enforcement middleware |
| [`multistore-sts`](https://docs.rs/multistore-sts) | [`crates/sts/`](crates/sts) | OIDC/STS token exchange (`AssumeRoleWithWebIdentity`) |
| [`multistore-oidc-provider`](https://docs.rs/multistore-oidc-provider) | [`crates/oidc-provider/`](crates/oidc-provider) | Outbound OIDC provider (JWT signing, JWKS, exchange, backend-cloud STS federation) |
| `multistore-static-config` | [`crates/static-config/`](crates/static-config) | Static config provider (buckets/roles/credentials) |
| [`multistore-path-mapping`](https://docs.rs/multistore-path-mapping) | [`crates/path-mapping/`](crates/path-mapping) | Hierarchical path-based backend resolution |
| [`multistore-cf-workers`](https://docs.rs/multistore-cf-workers) | [`crates/cf-workers/`](crates/cf-workers) | Cloudflare Workers runtime library (WASM) |

### Examples

| Crate | Path | Description |
| ----- | ---- | ----------- |
| `multistore-server` | [`examples/server/`](examples/server) | Tokio/Hyper native server for container deployments |
| `multistore-lambda` | [`examples/lambda/`](examples/lambda) | AWS Lambda runtime |
| `multistore-cf-workers-example` | [`examples/cf-workers/`](examples/cf-workers) | Cloudflare Workers example for edge deployments |

`multistore-static-config` is not published to crates.io; follow its source link for documentation. For per-crate responsibilities and the dependency graph, see [Crate Layout](https://developmentseed.org/multistore/architecture/crate-layout/) in the docs.

## Getting Started

See the [full documentation](https://developmentseed.org/multistore/getting-started/) for configuration, deployment, and usage guides.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and release process.

## License

[MIT](LICENSE)
