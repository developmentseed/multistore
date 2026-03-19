# multistore-metering

Usage metering and quota enforcement middleware for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Provides a `Middleware` implementation that hooks into the proxy dispatch pipeline to enforce quotas before requests proceed and record usage after responses complete. Integrators supply their own storage backends by implementing two traits:

- **`QuotaChecker`** — called pre-dispatch; return `Err(QuotaExceeded)` to reject with HTTP 429
- **`UsageRecorder`** — called post-dispatch with a `UsageEvent` (identity, operation, bytes, status)

## Usage

```rust
use multistore_metering::{MeteringMiddleware, NoopQuotaChecker, NoopRecorder};

// With both:
let metering = MeteringMiddleware::new(my_quota_checker, my_recorder);

// Or selectively:
let quota_only = MeteringMiddleware::new(my_quota_checker, NoopRecorder);
let record_only = MeteringMiddleware::new(NoopQuotaChecker, my_recorder);

let gateway = gateway.with_middleware(metering);
```
