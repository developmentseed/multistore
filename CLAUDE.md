# CLAUDE.md

## Codestyle

- Group logic into modules with high cohesion
- Add conceptual for public structs, traits, and functions that would be used by integrators building their own APIs

## Workflow

- Always run `cargo fmt` before committing.
- Always run `cargo clippy --fix --allow-dirty --allow-staged` before committing to catch lint issues.
- Always run `cargo check` and `cargo check -p multistore-cf-workers --target wasm32-unknown-unknown` to validate code
- Always update `docs/` to ensure documentation matches modules
- When making large changes, break work into smaller logical commits rather than one monolithic commit.
- Use conventional commits.
