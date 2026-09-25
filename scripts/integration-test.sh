#!/usr/bin/env bash
#
# Run the integration test suite locally — the same setup CI uses:
# RustFS (via docker compose) behind the Cloudflare Workers runtime (wrangler dev).
#
# Usage:
#   ./scripts/integration-test.sh [extra pytest args]
#   make test-integration
#
# RustFS lifecycle: if RustFS isn't running, this starts it and stops it again on
# exit (clean one-off run). If it's already up — e.g. you ran `docker compose
# up -d` to iterate — it's left running so repeated runs stay fast. wrangler dev
# is always stopped on exit.
#
# Prerequisites: docker, node/npx, uv (uvx), and the wasm32 Rust target
# (`rustup target add wasm32-unknown-unknown`). worker-build is installed
# automatically if missing.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PROXY_PORT:-8787}"
PROXY_URL="http://localhost:${PORT}"
WORKER_DIR="examples/cf-workers"

# Tear down RustFS on exit only if we started it. If it was already running
# (e.g. a dev who ran `docker compose up -d` to iterate), leave it warm so
# repeated runs stay fast and we don't stop a stack we didn't start.
STARTED_BACKEND=false
cleanup() {
  # Kill wrangler (and the workerd children it spawns).
  pkill -f "wrangler dev --config wrangler.integration.toml" 2>/dev/null || true
  if [ "$STARTED_BACKEND" = true ]; then
    echo "==> Stopping RustFS (started by this run)"
    docker compose down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if curl -sf -o /dev/null http://localhost:9000/health 2>/dev/null; then
  echo "==> RustFS already running — leaving it up after the run"
else
  STARTED_BACKEND=true
fi

echo "==> Starting RustFS + seeding buckets (docker compose)"
# Not `--wait`: the one-shot seeder (rustfs-init) exits, which `--wait` treats as
# a failure. Instead poll for a seeded public object — that confirms RustFS is up
# *and* the buckets are seeded.
docker compose up -d
for i in $(seq 1 30); do
  if curl -so /dev/null "http://localhost:9000/public-data/hello.txt"; then
    echo "    RustFS ready and seeded"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: RustFS did not become ready within 30s" >&2
    exit 1
  fi
  sleep 1
done

if ! command -v worker-build >/dev/null 2>&1; then
  echo "==> Installing worker-build"
  cargo install worker-build --version '^0.7'
fi

echo "==> Building worker (WASM)"
( cd "$WORKER_DIR" && worker-build --release )

# wrangler dev needs SESSION_TOKEN_KEY; generate a throwaway one if absent.
if [ ! -f "$WORKER_DIR/.dev.vars" ]; then
  echo "==> Writing throwaway $WORKER_DIR/.dev.vars"
  echo "SESSION_TOKEN_KEY=$(openssl rand -base64 32)" > "$WORKER_DIR/.dev.vars"
fi

echo "==> Starting wrangler dev on :${PORT}"
( cd "$WORKER_DIR" && npx wrangler dev --config wrangler.integration.toml --port "$PORT" ) \
  > /tmp/multistore-wrangler.log 2>&1 &

echo "==> Waiting for the proxy to accept requests"
for i in $(seq 1 60); do
  if curl -so /dev/null "${PROXY_URL}/"; then
    echo "    ready"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "ERROR: proxy did not start within 120s; wrangler log:" >&2
    tail -20 /tmp/multistore-wrangler.log >&2
    exit 1
  fi
  sleep 2
done

echo "==> Running integration tests"
PROXY_URL="$PROXY_URL" uvx --with pytest,boto3,requests \
  pytest tests/integration/ -v "$@"
