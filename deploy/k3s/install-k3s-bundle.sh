#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${K3S_ENV_FILE:-$ROOT_DIR/.env}"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

NAMESPACE="${K3S_NAMESPACE:-defensive-ai-gateway}"
IMAGE_DIR="${K3S_IMAGE_DIR:-$ROOT_DIR/images}"
WITH_SYSLOG=0
ALLOW_EMPTY_TOKEN=0

usage() {
  cat <<'EOF'
Usage:
  bash deploy/k3s/install-k3s-bundle.sh [options]

Options:
  --namespace NAME       Kubernetes namespace. Defaults to defensive-ai-gateway.
  --image-dir DIR        Directory containing exported image tar files. Defaults to ./images.
  --with-syslog          Also deploy the Vector syslog collector.
  --allow-empty-token    Permit an empty DEFENSIVE_AI_API_TOKEN for lab-only use.
  -h, --help             Show this help.

Required environment:
  DEFENSIVE_AI_API_TOKEN    Shared bearer token for gateway API.

Optional environment:
  DEFENSIVE_AI_LLM_API_KEY  API key for enterprise LLM Gateway.
  K3S_ENV_FILE              Env file to source. Defaults to bundle-root .env.
EOF
}

log() {
  printf '[k3s-install] %s\n' "$*"
}

die() {
  printf '[k3s-install] ERROR: %s\n' "$*" >&2
  exit 1
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verify_checksum() {
  tar_file="$1"
  checksum_file="$tar_file.sha256"
  [ -f "$checksum_file" ] || return 0

  expected="$(awk '{print $1; exit}' "$checksum_file")"
  actual="$(sha256_of "$tar_file")"
  if [ "$expected" != "$actual" ]; then
    die "checksum mismatch for $tar_file"
  fi
  log "checksum ok: $tar_file"
}

import_image() {
  tar_file="$1"
  verify_checksum "$tar_file"
  log "importing image: $tar_file"
  if command -v k3s >/dev/null 2>&1; then
    sudo k3s ctr images import "$tar_file"
  elif command -v ctr >/dev/null 2>&1; then
    sudo ctr -n k8s.io images import "$tar_file"
  else
    die "neither k3s nor ctr was found; cannot import image tar"
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --namespace)
      [ "$#" -ge 2 ] || die "--namespace requires a value"
      NAMESPACE="$2"
      shift 2
      ;;
    --image-dir)
      [ "$#" -ge 2 ] || die "--image-dir requires a value"
      IMAGE_DIR="$2"
      shift 2
      ;;
    --with-syslog)
      WITH_SYSLOG=1
      shift
      ;;
    --allow-empty-token)
      ALLOW_EMPTY_TOKEN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

command -v kubectl >/dev/null 2>&1 || die "kubectl not found"

if [ -z "${DEFENSIVE_AI_API_TOKEN:-}" ] && [ "$ALLOW_EMPTY_TOKEN" -ne 1 ]; then
  die "DEFENSIVE_AI_API_TOKEN is required. Copy .env.example to .env and edit it, or pass --allow-empty-token for lab-only use."
fi

if [ -d "$IMAGE_DIR" ]; then
  found_tar=0
  for tar_file in "$IMAGE_DIR"/*.tar; do
    [ -f "$tar_file" ] || continue
    found_tar=1
    import_image "$tar_file"
  done
  if [ "$found_tar" -eq 0 ]; then
    log "no image tar found in $IMAGE_DIR; k3s will use already-present images or try image pull"
  fi
else
  log "image directory not found: $IMAGE_DIR; k3s will use already-present images or try image pull"
fi

log "applying gateway manifests"
kubectl apply -f "$ROOT_DIR/deploy/k3s/gateway.yaml"

log "updating runtime secret"
kubectl -n "$NAMESPACE" create secret generic defensive-ai-gateway-secrets \
  --from-literal=DEFENSIVE_AI_API_TOKEN="${DEFENSIVE_AI_API_TOKEN:-}" \
  --from-literal=DEFENSIVE_AI_LLM_API_KEY="${DEFENSIVE_AI_LLM_API_KEY:-}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$NAMESPACE" rollout restart deployment/defensive-ai-gateway
kubectl -n "$NAMESPACE" rollout status deployment/defensive-ai-gateway

if [ "$WITH_SYSLOG" -eq 1 ]; then
  log "applying syslog collector manifests"
  kubectl apply -f "$ROOT_DIR/deploy/k3s/syslog-collector-vector.yaml"
  kubectl -n "$NAMESPACE" rollout status deployment/syslog-collector-vector
fi

log "deployment complete"
log "health check: kubectl -n $NAMESPACE port-forward svc/defensive-ai-gateway 8080:8080"
