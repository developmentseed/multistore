# Contributing

## Development

This project uses [conventional commits](https://www.conventionalcommits.org/).

```bash
# Format
cargo fmt

# Lint
cargo clippy --fix --allow-dirty --allow-staged

# Check (native)
cargo check

# Check (WASM)
cargo check -p multistore-cf-workers --target wasm32-unknown-unknown

# Lint (WASM) — the Workers crates are not in `default-members`, so lint them explicitly
cargo clippy -p multistore-cf-workers -p multistore-cf-workers-example --target wasm32-unknown-unknown -- -D warnings

# Unit + doc tests
cargo test

# Integration tests (RustFS via docker compose behind wrangler dev; mirrors CI)
make test-integration
```

### Lints and MSRV

Lint levels live in `[workspace.lints]` in the root `Cargo.toml`; every crate opts in with `[lints] workspace = true`. Beyond clippy's defaults the workspace warns on `missing_docs` (document every `pub` item) and `clippy::unwrap_used` (return an error, or use `expect` with a message that states the invariant). Tests are exempt from the unwrap lint via `clippy.toml`. CI runs clippy with `-D warnings`, so a new warning fails the build.

The minimum supported Rust version is declared as `rust-version` in the root `Cargo.toml`. It is set by the dependency tree; raise it only when a dependency forces it.

## Release Process

### Publishable Crates

The following crates are published to crates.io (in dependency order):

1. `multistore`
2. `multistore-metering`
3. `multistore-path-mapping`
4. `multistore-sts`
5. `multistore-oidc-provider`
6. `multistore-cf-workers`

### Automated Releases

Releases are managed by [release-please](https://github.com/googleapis/release-please). On every push to `main`, it maintains a PR that bumps versions and updates the changelog based on conventional commits.

When that PR is merged, release-please creates a GitHub release, which triggers the publish workflow (`.github/workflows/release.yml`). The workflow:

1. Derives the crate version from the git tag (e.g. `v0.2.0` → `0.2.0`)
2. Patches the workspace version in `Cargo.toml`
3. Dry-runs all crates to catch packaging errors
4. Publishes all crates to crates.io using OIDC trusted publishing

### Pre-releases

To publish a pre-release (e.g. `0.2.0-alpha.1`):

1. Go to **Releases → Draft a new release** on GitHub
2. Create a new tag matching `v<semver>` (e.g. `v0.2.0-alpha.1`)
3. Check **"Set as a pre-release"**
4. Publish the release

The same workflow runs automatically. The version in the tag overrides `Cargo.toml`, so no source changes are needed. crates.io treats any version with a pre-release identifier as a pre-release — it won't resolve for `^0.2` ranges and won't appear as the latest version.
