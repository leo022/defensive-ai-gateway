#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="$ROOT_DIR/deploy/k3s/syslog-collector-vector.yaml"
OUTPUT="${1:-$ROOT_DIR/data/vector/vector.toml}"
OUTPUT_DIR="$(dirname -- "$OUTPUT")"

[ -f "$SOURCE" ] || {
  printf 'missing Vector source manifest: %s\n' "$SOURCE" >&2
  exit 1
}

mkdir -p "$OUTPUT_DIR"
TEMP_OUTPUT="$(mktemp "$OUTPUT_DIR/.vector.toml.XXXXXX")"

awk '
  /^  vector\.toml: \|$/ { capture = 1; next }
  capture && /^---$/ { exit }
  capture { sub(/^    /, ""); print }
' "$SOURCE" \
  | sed \
    -e 's|http://defensive-ai-gateway:8080|http://127.0.0.1:8080|g' \
    -e 's|address = "0.0.0.0:8686"|address = "127.0.0.1:8686"|' \
  > "$TEMP_OUTPUT"

[ -s "$TEMP_OUTPUT" ] || {
  printf 'failed to extract Vector TOML from %s\n' "$SOURCE" >&2
  exit 1
}

chmod 0644 "$TEMP_OUTPUT"
mv "$TEMP_OUTPUT" "$OUTPUT"
printf 'rendered single-host Vector configuration: %s\n' "$OUTPUT"
