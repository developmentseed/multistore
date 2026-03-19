# multistore-path-mapping

Hierarchical path mapping for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Translates hierarchical URL paths (e.g., `/{account}/{product}/{key}`) into flat internal bucket names (e.g., `account--product`) while configuring list rewrite rules so S3 XML responses display the expected key structure.

## Key Types

**`PathMapping`** — configuration for how URL segments map to buckets:
- `bucket_segments` — number of leading path segments that form the bucket name
- `bucket_separator` — join character (e.g., `--` produces `account--product`)
- `display_bucket_segments` — how many segments form the display name in XML responses

**`MappedPath`** — result of parsing a path, containing the internal bucket name, remaining key, display bucket name, and key prefix for list rewrites.

**`MappedRegistry<R>`** — wraps any `BucketRegistry` implementation, applying path-based routing transparently.

## Usage

```rust
use multistore_path_mapping::{PathMapping, MappedRegistry};

let mapping = PathMapping {
    bucket_segments: 2,
    bucket_separator: "--".into(),
    display_bucket_segments: 1,
};

// Wrap an existing BucketRegistry:
let registry = MappedRegistry::new(inner_registry, mapping);

// Requests to /acme/data/file.parquet resolve to internal bucket "acme--data"
// with key "file.parquet", and LIST responses show bucket name "acme".
```
