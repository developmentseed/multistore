#!/usr/bin/env bash
#
# Run the integration test suite locally — the same setup CI uses:
# MinIO (via docker compose) behind the Cloudflare Workers runtime (wrangler dev).
#
# Usage:
#   ./scripts/integration-test.sh [extra pytest args]
#   make test-integration
#
# Prerequisites: docker, node/npx, uv (uvx), and the wasm32 Rust target
# (`rustup target add wasm32-unknown-unknown`). worker-build is installed
# automatically if missing.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PROXY_PORT:-8787}"
PROXY_URL="http://localhost:${PORT}"
WORKER_DIR="examples/cf-workers"

cleanup() {
  # Kill wrangler (and the workerd children it spawns).
  pkill -f "wrangler dev --config wrangler.integration.toml" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Starting MinIO + seeding buckets (docker compose)"
# Not `--wait`: the one-shot seeder (minio-init) exits, which `--wait` treats as
# a failure. Instead poll for a seeded public object — that confirms MinIO is up
# *and* the buckets are seeded.
docker compose up -d
for i in $(seq 1 30); do
  if curl -so /dev/null "http://localhost:9000/public-data/hello.txt"; then
    echo "    MinIO ready and seeded"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: MinIO did not become ready within 30s" >&2
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
