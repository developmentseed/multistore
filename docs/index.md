---
layout: home

hero:
  name: Multistore
  text: A multi-runtime S3 gateway proxy with authentication, authorization, and zero-copy passthrough.
  tagline: Built in Rust. Deploy as a native server or Cloudflare Worker.
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/
    - theme: alt
      text: Configuration
      link: /configuration/
    - theme: alt
      text: View on GitHub
      link: https://github.com/developmentseed/multistore

features:
  - title: Unified Interface
    details: One stable URL per dataset, regardless of which object storage provider hosts the bytes. Backend migrations are invisible to data consumers.
  - title: Native S3 Compatibility
    details: Works with aws-cli, boto3, DuckDB, obstore, GDAL, and any S3-compatible client. No custom SDK — just set the endpoint URL.
  - title: Flexible Auth
    details: OIDC token exchange for both frontend (user/machine identity) and backend (cloud storage credentials). No long-lived keys anywhere in the chain.
  - title: Multi-Runtime
    details: Same core logic deploys as a native Tokio/Hyper server in containers or as a Cloudflare Worker at the edge.
  - title: Zero-Copy Streaming
    details: Presigned URLs enable direct streaming between clients and backends. No buffering, no double-handling of request or response bodies.
  - title: Extensible
    details: Pluggable traits for request resolution, configuration, and backend I/O. Build your own proxy with custom auth, namespace mapping, and storage backends.
---

## How It Works

```mermaid
flowchart LR
    Clients["S3 Clients<br>(aws-cli, boto3, SDKs)"]

    subgraph Proxy["multistore-proxy"]
        Auth["Auth<br>(STS, OIDC, SigV4)"]
        Core["Core<br>(Proxy Handler)"]
        Config["Config<br>(Static, HTTP, DynamoDB, Postgres)"]
    end

    Backend["Backend Stores<br>(AWS S3, MinIO, R2, Azure, GCS)"]

    Clients <--> Proxy
    Proxy <--> Backend
```

The proxy sits between S3-compatible clients and backend object stores. It authenticates incoming requests, authorizes them against configured scopes, and forwards them to the appropriate backend using presigned URLs for zero-copy streaming.

## Get Started

The [Getting Started](/getting-started/) guide walks you through setting up, configuring, and deploying the proxy — defining backends, buckets, roles, authentication, and extending with custom resolvers and providers.
