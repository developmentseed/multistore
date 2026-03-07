# CLAUDE.md

## Codestyle

- Group logic into modules with high cohesion
- Add conceptual documentation for public structs, traits, and functions that would be used by integrators building their own APIs
- This codebase is still in development. No need to support legacy

## Workflow

- Always run `cargo fmt` before committing.
- Always run `cargo clippy --fix --allow-dirty --allow-staged` before committing to catch lint issues.
- Always update `docs/` to ensure documentation matches modules
- Always run `cargo check` and `cargo check -p multistore-cf-workers --target wasm32-unknown-unknown` to validate code
- When making large changes, break work into smaller logical commits rather than one monolithic commit.
- Use conventional commits.
