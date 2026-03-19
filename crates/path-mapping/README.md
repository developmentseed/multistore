# multistore-path-mapping

Hierarchical path mapping for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Translates hierarchical URL paths into flat internal bucket names while configuring list rewrite rules so S3 XML responses display the expected key structure.

For example, with `bucket_segments: 2` and `separator: "--"`:

- Request to `/acme/data/file.parquet` resolves to internal bucket `acme--data` with key `file.parquet`
- LIST responses rewrite keys to show the hierarchical structure

## Usage

```rust
use multistore_path_mapping::{PathMapping, MappedRegistry};

let mapping = PathMapping {
    bucket_segments: 2,
    bucket_separator: "--".into(),
    display_bucket_segments: 1,
};

// Wrap any BucketRegistry to add path-based routing:
let registry = MappedRegistry::new(inner_registry, mapping);
```
