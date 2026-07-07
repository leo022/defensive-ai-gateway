#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT_DIR/dist/k3s-images"
GATEWAY_IMAGE="${GATEWAY_IMAGE:-defensive-ai-gateway:latest}"
VECTOR_IMAGE="${VECTOR_IMAGE:-timberio/vector:0.39.0-alpine}"
PLATFORM="${PLATFORM:-linux/amd64}"
INCLUDE_VECTOR=0

usage() {
  cat <<'EOF'
Usage:
  bash deploy/k3s/build-offline-images.sh [options]

Options:
  --out-dir DIR        Output directory. Defaults to dist/k3s-images.
  --image IMAGE        Gateway image tag. Defaults to defensive-ai-gateway:latest.
  --platform PLATFORM  Image platform. Defaults to linux/amd64.
  --include-vector     Pull and export timberio/vector:0.39.0-alpine for syslog collector.
  -h, --help           Show this help.
EOF
}

checksum() {
  local file="$1"
  local base
  base="$(basename "$file")"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | sed "s#  .*#  $base#" > "$file.sha256"
  else
    shasum -a 256 "$file" | sed "s#  .*#  $base#" > "$file.sha256"
  fi
}

image_file_name() {
  printf '%s\n' "$1" | tr '/:' '--'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir)
      [ "$#" -ge 2 ] || { echo "--out-dir requires a value" >&2; exit 1; }
      OUT_DIR="$2"
      shift 2
      ;;
    --image)
      [ "$#" -ge 2 ] || { echo "--image requires a value" >&2; exit 1; }
      GATEWAY_IMAGE="$2"
      shift 2
      ;;
    --platform)
      [ "$#" -ge 2 ] || { echo "--platform requires a value" >&2; exit 1; }
      PLATFORM="$2"
      shift 2
      ;;
    --include-vector)
      INCLUDE_VECTOR=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 1
      ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }
docker info >/dev/null

mkdir -p "$OUT_DIR"

echo "[build] gateway image: $GATEWAY_IMAGE"
echo "[build] platform: $PLATFORM"
docker buildx build --platform "$PLATFORM" --load -t "$GATEWAY_IMAGE" -f "$ROOT_DIR/deploy/docker/Dockerfile" "$ROOT_DIR"

GATEWAY_TAR="$OUT_DIR/$(image_file_name "$GATEWAY_IMAGE").tar"
docker save "$GATEWAY_IMAGE" -o "$GATEWAY_TAR"
checksum "$GATEWAY_TAR"
echo "[build] wrote $GATEWAY_TAR"

if [ "$INCLUDE_VECTOR" -eq 1 ]; then
  echo "[build] vector image: $VECTOR_IMAGE"
  docker pull --platform "$PLATFORM" "$VECTOR_IMAGE"
  VECTOR_TAR="$OUT_DIR/$(image_file_name "$VECTOR_IMAGE").tar"
  docker save "$VECTOR_IMAGE" -o "$VECTOR_TAR"
  checksum "$VECTOR_TAR"
  echo "[build] wrote $VECTOR_TAR"
fi
