#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-"$ROOT_DIR/../outputs"}"
mkdir -p "$OUT_DIR"

ARCHIVE="$OUT_DIR/defensive-ai-gateway-mvp.tar.gz"

cd "$ROOT_DIR"
tar \
  --exclude="./data" \
  --exclude="./__pycache__" \
  --exclude="./.pytest_cache" \
  --exclude="./.DS_Store" \
  --exclude="./*.pyc" \
  -czf "$ARCHIVE" \
  .

echo "$ARCHIVE"
