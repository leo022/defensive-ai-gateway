#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT_DIR/dist/k3s-images"
PLATFORM="${PLATFORM:-linux/amd64}"
INCLUDE_VECTOR=0
VCS_REF="${VCS_REF:-$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)}"
REVISION_TAG="$(printf '%.12s' "$VCS_REF" | tr -cd 'A-Za-z0-9._-')"
[ -n "$REVISION_TAG" ] || REVISION_TAG="unversioned"
GATEWAY_IMAGE="${GATEWAY_IMAGE:-defensive-ai-gateway:$REVISION_TAG}"
VECTOR_IMAGE="${VECTOR_IMAGE:-}"
PYTHON_BASE_IMAGE="${PYTHON_BASE_IMAGE:-}"
APP_VERSION="${APP_VERSION:-$(git -C "$ROOT_DIR" describe --always 2>/dev/null || echo "$REVISION_TAG")}"
ALLOW_DIRTY=0

usage() {
  cat <<'EOF'
Usage:
  bash deploy/k3s/build-offline-images.sh [options]

Options:
  --out-dir DIR        Output directory. Defaults to dist/k3s-images.
  --image IMAGE        Temporary build tag/repository. The exported ref is
                       always retagged from the resulting image content ID.
  --python-base IMAGE  Digest-pinned Python base image used for the release build.
  --vector-image IMAGE Digest-pinned Vector image required with --include-vector.
  --platform PLATFORM  Image platform. Defaults to linux/amd64.
  --include-vector     Pull and export the digest-pinned Vector image.
  --allow-dirty        Explicitly build a non-release image from a dirty worktree.
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

is_digest_ref() {
  ref="$1"
  digest="${ref##*@sha256:}"
  [ "$digest" != "$ref" ] || return 1
  [ "${#digest}" -eq 64 ] || return 1
  case "$digest" in *[!0-9a-fA-F]*) return 1 ;; esac
  return 0
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
    --python-base)
      [ "$#" -ge 2 ] || { echo "--python-base requires a value" >&2; exit 1; }
      PYTHON_BASE_IMAGE="$2"
      shift 2
      ;;
    --vector-image)
      [ "$#" -ge 2 ] || { echo "--vector-image requires a value" >&2; exit 1; }
      VECTOR_IMAGE="$2"
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
    --allow-dirty)
      ALLOW_DIRTY=1
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

if [ "$ALLOW_DIRTY" -ne 1 ] && [ -n "$(git -C "$ROOT_DIR" status --porcelain 2>/dev/null || true)" ]; then
  echo "refusing to build release images from a dirty worktree; commit/stash changes or pass --allow-dirty" >&2
  exit 1
fi
case "$GATEWAY_IMAGE" in *@*) echo "gateway build reference must be a tag, not a digest" >&2; exit 1 ;; esac
case "${GATEWAY_IMAGE##*/}" in
  *:*) ;;
  *) echo "gateway build reference must include an explicit temporary tag" >&2; exit 1 ;;
esac
is_digest_ref "$PYTHON_BASE_IMAGE" || {
  echo "--python-base (or PYTHON_BASE_IMAGE) must pin python:3.11-slim by sha256 digest" >&2
  exit 1
}
if [ "$INCLUDE_VECTOR" -eq 1 ]; then
  is_digest_ref "$VECTOR_IMAGE" || {
    echo "--vector-image (or VECTOR_IMAGE) must pin Vector by sha256 digest" >&2
    exit 1
  }
fi

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }
docker info >/dev/null

mkdir -p "$OUT_DIR"

echo "[build] gateway image: $GATEWAY_IMAGE"
echo "[build] platform: $PLATFORM"
docker buildx build \
  --platform "$PLATFORM" \
  --load \
  --build-arg "APP_VERSION=$APP_VERSION" \
  --build-arg "VCS_REF=$VCS_REF" \
  --build-arg "PYTHON_BASE_IMAGE=$PYTHON_BASE_IMAGE" \
  -t "$GATEWAY_IMAGE" \
  -f "$ROOT_DIR/deploy/docker/Dockerfile" \
  "$ROOT_DIR"

BUILT_PLATFORM="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$GATEWAY_IMAGE")"
if [ "$BUILT_PLATFORM" != "$PLATFORM" ]; then
  echo "built image platform mismatch: expected $PLATFORM, got $BUILT_PLATFORM" >&2
  exit 1
fi
echo "[build] verified image platform: $BUILT_PLATFORM"

# A Git tag can be reused by dirty or rebuilt sources. Export the gateway under
# a content-derived tag so every rollback reference names exactly one image ID.
GATEWAY_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$GATEWAY_IMAGE")"
case "$GATEWAY_IMAGE_ID" in sha256:????????????????????????????????????????????????????????????????) ;; *)
  echo "built gateway image did not expose a sha256 content ID" >&2
  exit 1
;; esac
GATEWAY_REPOSITORY="${GATEWAY_IMAGE%:*}"
[ -n "$GATEWAY_REPOSITORY" ] || GATEWAY_REPOSITORY="defensive-ai-gateway"
GATEWAY_IMAGE="$GATEWAY_REPOSITORY:sha256-${GATEWAY_IMAGE_ID#sha256:}"
docker tag "$GATEWAY_IMAGE_ID" "$GATEWAY_IMAGE"
echo "[build] content-addressed gateway ref: $GATEWAY_IMAGE"

GATEWAY_TAR="$OUT_DIR/$(image_file_name "$GATEWAY_IMAGE").tar"
docker save "$GATEWAY_IMAGE" -o "$GATEWAY_TAR"
checksum "$GATEWAY_TAR"
printf '%s\n' "$GATEWAY_IMAGE" > "$GATEWAY_TAR.ref"
echo "[build] wrote $GATEWAY_TAR"

if [ "$INCLUDE_VECTOR" -eq 1 ]; then
  echo "[build] vector image: $VECTOR_IMAGE"
  docker pull --platform "$PLATFORM" "$VECTOR_IMAGE"
  VECTOR_TAR="$OUT_DIR/$(image_file_name "$VECTOR_IMAGE").tar"
  docker save "$VECTOR_IMAGE" -o "$VECTOR_TAR"
  checksum "$VECTOR_TAR"
  printf '%s\n' "$VECTOR_IMAGE" > "$VECTOR_TAR.ref"
  echo "[build] wrote $VECTOR_TAR"
fi
