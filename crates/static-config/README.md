# multistore-static-config

Static file-based configuration provider for the [`multistore`](https://crates.io/crates/multistore) S3 proxy gateway.

## Overview

Loads bucket, credential, and role configurations from TOML or JSON files at startup. Implements both `BucketRegistry` and `CredentialRegistry` from the multistore core, making it suitable for simple deployments or development environments.

## Key Types

**`StaticProvider`** — the main provider. Implements `BucketRegistry` (bucket lookup, authorization, listing) and `CredentialRegistry` (credential and role lookup).

**`StaticConfig`** — deserializable root configuration with `validate()` for checking empty names, duplicates, and configuration consistency.

## Usage

```rust
use multistore_static_config::StaticProvider;

// From a TOML file:
let provider = StaticProvider::from_file("config.toml")?;

// Or from a string:
let provider = StaticProvider::from_toml(toml_str)?;
let provider = StaticProvider::from_json(json_str)?;

// Use as both registries:
let gateway = ProxyGateway::new(
    backend,
    provider.clone(),  // as BucketRegistry
    provider,          // as CredentialRegistry
    virtual_host_domain,
);
```

## Configuration Fields

- `owner_id` / `owner_display_name` — bucket owner info for ListBuckets responses
- `buckets` — list of `BucketConfig` entries (name, backend URL, auth, scopes)
- `credentials` — list of `StoredCredential` entries (access key ID, secret)
- `roles` — list of `RoleConfig` entries (for OIDC/STS trust policies)
