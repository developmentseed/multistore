# multistore-cf-workers

Cloudflare Workers runtime adapters for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Provides everything needed to run the multistore proxy on Cloudflare Workers: a `ProxyBackend` implementation using the Fetch API, zero-copy request/response streaming via native `ReadableStream`, an `object_store` HTTP connector, and response conversion helpers.

This crate only compiles for `wasm32-unknown-unknown`.

## Key Types

**`WorkerBackend`** — implements `ProxyBackend` using the Workers Fetch API. Supports zero-copy PUT streaming (passes the incoming `ReadableStream` directly to the backend) and `Range` request cache bypass.

**`FetchConnector`** — `HttpConnector` implementation that bridges `object_store` HTTP requests to the Workers Fetch API. Handles the `!Send` boundary via `spawn_local` and oneshot channels.

**`JsBody`** — wrapper around `Option<web_sys::ReadableStream>` for zero-copy body forwarding. Use `collect_js_body()` to materialize small payloads (e.g., multipart responses) into `Bytes`.

**`NoopCredentialRegistry`** — `CredentialRegistry` that always returns `None`, for anonymous-only deployments.

**`WorkerSubscriber`** — lightweight `tracing::Subscriber` that routes log events to `console.log`/`console.warn`/`console.error`.

## Response Helpers

- `proxy_result_to_ws_response()` — convert buffered proxy responses to `web_sys::Response`
- `forward_response_to_ws()` — convert streaming forwarded responses (zero-copy)
- `ws_error_response()` / `ws_xml_response()` — build error and XML responses
- `convert_ws_headers()` / `http_headermap_to_ws_headers()` — header conversion

## Feature Flags

- `azure` — Azure Blob Storage backend support
- `gcp` — Google Cloud Storage backend support
