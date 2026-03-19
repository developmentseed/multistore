# multistore-static-config

Static file-based configuration provider for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Loads bucket, credential, and role configurations from TOML or JSON files at startup. Implements both `BucketRegistry` and `CredentialRegistry`, making it suitable for simple deployments or development environments.

## Usage

```rust
use multistore_static_config::StaticProvider;

let provider = StaticProvider::from_file("config.toml")?;

let gateway = ProxyGateway::new(
    backend,
    provider.clone(),  // as BucketRegistry
    provider,          // as CredentialRegistry
    virtual_host_domain,
);
```
