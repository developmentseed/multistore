# multistore-metering

Usage metering and quota enforcement middleware for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

This crate provides a `Middleware` implementation that hooks into the multistore proxy dispatch pipeline to:

1. **Enforce quotas** before requests proceed (pre-dispatch)
2. **Record usage** after responses complete (post-dispatch)

Integrators supply their own storage backends by implementing two traits.

## Traits

**`QuotaChecker`** — called before dispatch with the caller's identity, operation, bucket, estimated bytes (from `Content-Length`), and source IP. Return `Err(QuotaExceeded)` to reject with HTTP 429.

**`UsageRecorder`** — called after dispatch with a `UsageEvent` containing the request ID, identity, operation, bucket, HTTP status, actual bytes transferred, and whether the request was forwarded. Recording is fire-and-forget; failures do not affect the response.

## Usage

```rust
use multistore_metering::{MeteringMiddleware, NoopQuotaChecker, NoopRecorder};

// With real implementations:
let metering = MeteringMiddleware::new(my_quota_checker, my_recorder);

// Or selectively — quota only, recording only:
let quota_only = MeteringMiddleware::new(my_quota_checker, NoopRecorder);
let record_only = MeteringMiddleware::new(NoopQuotaChecker, my_recorder);

// Register as middleware on the gateway:
let gateway = gateway.with_middleware(metering);
```

## No-op Implementations

- `NoopQuotaChecker` — always allows requests
- `NoopRecorder` — discards usage events
