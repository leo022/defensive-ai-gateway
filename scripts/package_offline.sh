#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/../outputs"
ALLOW_DIRTY=0

usage() {
  cat <<'EOF'
Usage: bash scripts/package_offline.sh [OUT_DIR] [--allow-dirty]

Creates an atomic source archive. Secret-bearing .env files are always excluded.
A dirty Git worktree is rejected unless --allow-dirty is explicitly supplied.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      printf '[package] ERROR: unknown option: %s\n' "$1" >&2
      exit 1
      ;;
    *)
      OUT_DIR="$1"
      shift
      ;;
  esac
done

if [ "$ALLOW_DIRTY" -ne 1 ] && [ -n "$(git -C "$ROOT_DIR" status --porcelain 2>/dev/null || true)" ]; then
  printf '[package] ERROR: refusing to package a dirty worktree; commit/stash changes or pass --allow-dirty for a non-release artifact\n' >&2
  exit 1
fi

umask 077
mkdir -p "$OUT_DIR"

ARCHIVE="$OUT_DIR/defensive-ai-gateway-mvp.tar.gz"
WORK_DIR="$(mktemp -d "$OUT_DIR/.defensive-ai-gateway-mvp.XXXXXX")"
TEMP_ARCHIVE="$WORK_DIR/defensive-ai-gateway-mvp.tar.gz"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$ROOT_DIR"
tar \
  --exclude="./.git" \
  --exclude="./data" \
  --exclude="./dist" \
  --exclude="./outputs" \
  --exclude="./.env" \
  --exclude="./.env.*" \
  --exclude="./*.env" \
  --exclude="*/.env" \
  --exclude="*/.env.*" \
  --exclude="*.env" \
  --exclude="./config/prod.yaml" \
  --exclude="./__pycache__" \
  --exclude="./.pytest_cache" \
  --exclude="./.DS_Store" \
  --exclude="./*.pyc" \
  -czf "$TEMP_ARCHIVE" \
  .

mv -f "$TEMP_ARCHIVE" "$ARCHIVE"
echo "$ARCHIVE"
