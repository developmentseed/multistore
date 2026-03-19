# multistore-cf-workers

Cloudflare Workers runtime adapters for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Provides everything needed to run the multistore proxy on Cloudflare Workers: a `ProxyBackend` implementation using the Fetch API, zero-copy request/response streaming via native `ReadableStream`, an `object_store` HTTP connector, and response conversion helpers.

This crate only compiles for `wasm32-unknown-unknown`.

## Feature Flags

- `azure` — Azure Blob Storage backend support
- `gcp` — Google Cloud Storage backend support
