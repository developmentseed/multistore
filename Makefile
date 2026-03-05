.PHONY: check test run-server run-workers ci docs

build: build-workers

build-workers:
	npx wrangler build --cwd examples/cf-workers

check:
	cargo check

check-wasm:
	cargo check -p multistore-cf-workers --target wasm32-unknown-unknown

fmt:
	cargo fmt -- --check
fmt-fix:
	cargo fmt

clippy:
	cargo clippy -- -D warnings
clippy-fix:
	cargo clippy --fix --allow-dirty --allow-staged

test:
	cargo test

run-server:
	cargo run -p multistore-server -- $(ARGS)

run-workers:
	npx wrangler dev --cwd examples/cf-workers

ci-fast: fmt clippy check-wasm
ci: ci-fast test

docs:
	npm run --prefix docs docs:dev
