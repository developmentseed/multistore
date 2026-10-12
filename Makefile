.PHONY: check test test-integration run-server run-workers ci docs

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
clippy-wasm:
	cargo clippy -p multistore-cf-workers -p multistore-cf-workers-example --target wasm32-unknown-unknown -- -D warnings
clippy-fix:
	cargo clippy --fix --allow-dirty --allow-staged

test:
	cargo test

# Run the integration suite locally: RustFS (docker compose) + the Workers
# runtime (wrangler dev), mirroring CI. Pass extra pytest args via ARGS.
test-integration:
	./scripts/integration-test.sh $(ARGS)

run-server:
	cargo run -p multistore-server -- $(ARGS)

run-workers:
	npx wrangler dev --cwd examples/cf-workers

ci-fast: fmt clippy clippy-wasm check-wasm
ci: ci-fast test

docs:
	npm run --prefix docs docs:dev
