# CLAUDE.md

## Codestyle

- Group logic into modules with high cohesion
- Add conceptual documentation for public structs, traits, and functions that would be used by integrators building their own APIs
- This codebase is still in development. No need to support legacy

## Workflow

- Use ./.plans for any agent planning documents
- Always run `cargo fmt` before committing.
- Always run `cargo clippy --fix --allow-dirty --allow-staged` before committing to catch lint issues.
- Always update `docs/` to ensure documentation matches modules
- Always run `cargo check` and `cargo check -p multistore-cf-workers --target wasm32-unknown-unknown` to validate code
- When making large changes, break work into smaller logical commits rather than one monolithic commit.
- When fixing bugs, first write a failing test and then fix the bug to ensure that the fix resolved the issue.
- Review codebase for dead code after refactoring.
- Use conventional commits.

## Pull request descriptions

Structure PR bodies with two required sections (plus an optional `## Test plan`):

- **`## What I'm changing`** — lead with the motivation (the "why"). State the problem, the user-visible symptom, or the constraint that forced the change before describing the change itself. A reviewer should understand *why this PR exists* from this section alone, without reading the diff.
- **`## How I did it`** — bulleted, per-module or per-file. For each notable change, name the symbol or file and explain what changed and why that approach. Mention refactors that exist only to enable the main change so they don't look like scope creep.
- **`## Test plan`** (optional) — checklist of verification commands run (e.g. `cargo check`, `cargo clippy`, target-specific builds) and any manual checks.

Keep prose tight. Prefer concrete identifiers (`RewriteResult`, `resolve_request_with_metadata`) over vague phrases ("the helper"). Don't restate the diff — explain what the diff doesn't.
