#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${K3S_ENV_FILE:-$ROOT_DIR/.env}"
NAMESPACE="defensive-ai-gateway"
IMAGE_DIR=""
WITH_SYSLOG=0
SYSLOG_CONSOLE_CONFIG=""
DEMO_MODE=0
PREFLIGHT_ONLY=0
SKIP_BACKUP=0
ROLLBACK_ID=""
SECRET_FILE=""
RENDER_DIR=""
BACKUP_ID=""
PREVIOUS_IMAGE=""
BACKUP_COMPLETE=0
SECRET_COPY_FILE=""
VECTOR_COPY_FILE=""
SYSLOG_POLICY_FILE=""
WORKLOAD_SPEC_DIR=""

usage() {
  cat <<'EOF'
Usage: bash deploy/k3s/install-k3s-bundle.sh [options]

Production is the default: strong distinct role tokens, TLS ingress, source
allowlisting, two-person approval, immutable images, and a pre-upgrade DB backup.

Options:
  --image-dir DIR        Exported image tar directory. Defaults to ./images.
  --with-syslog          Deploy Vector; requires a distinct ingest token and source CIDRs.
  --syslog-console-config FILE
                         Read a console-exported Syslog source-CIDR file.
  --demo-mode            Explicitly use tokenless hostPort HTTP for an isolated demo.
  --require-token        Deprecated no-op; production is already the default.
  --allow-empty-token    Deprecated alias for --demo-mode.
  --skip-backup          Skip the pre-upgrade SQLite backup (break-glass only).
  --rollback BACKUP_ID   Restore a backup recorded by an earlier installation.
  --preflight-only       Validate environment values without touching a cluster.
  -h, --help             Show this help.

Production environment:
  DEFENSIVE_AI_API_TOKEN, DEFENSIVE_AI_INGEST_TOKEN,
  DEFENSIVE_AI_OPERATOR_TOKEN, DEFENSIVE_AI_APPROVER_TOKEN
  DEFENSIVE_AI_PUBLIC_HOST, DEFENSIVE_AI_TLS_SECRET,
  DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS
  DEFENSIVE_AI_LLM_PROVIDER, DEFENSIVE_AI_LLM_ENDPOINT,
  DEFENSIVE_AI_LLM_MODEL, DEFENSIVE_AI_LLM_ALLOWED_HOSTS
  DEFENSIVE_AI_LLM_API_KEY (gateway provider only)
  DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS (with --with-syslog)
EOF
}

log() {
  printf '[k3s-install] %s\n' "$*"
}

die() {
  printf '[k3s-install] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  [ -z "$SECRET_FILE" ] || rm -f "$SECRET_FILE"
  [ -z "$SECRET_COPY_FILE" ] || rm -f "$SECRET_COPY_FILE"
  [ -z "$VECTOR_COPY_FILE" ] || rm -f "$VECTOR_COPY_FILE"
  [ -z "$SYSLOG_POLICY_FILE" ] || rm -f "$SYSLOG_POLICY_FILE"
  [ -z "$RENDER_DIR" ] || rm -rf "$RENDER_DIR"
  [ -z "$WORKLOAD_SPEC_DIR" ] || rm -rf "$WORKLOAD_SPEC_DIR"
}
trap cleanup EXIT

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

load_environment() {
  if [ ! -f "$ENV_FILE" ]; then
    return
  fi
  mode="$(file_mode "$ENV_FILE")" || die "cannot read permissions for $ENV_FILE"
  case "$mode" in
    *[!0-7]*) die "invalid permissions on $ENV_FILE" ;;
  esac
  # Any group/other permission can disclose long-lived credentials.
  [ "$((8#$mode & 077))" -eq 0 ] || die "$ENV_FILE must be chmod 600 (current mode: $mode)"
  set -a
  # This is an administrator-controlled file and is intentionally shell-compatible.
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
}

load_syslog_console_config() {
  syslog_console_file="$1"
  [ -f "$syslog_console_file" ] && [ -r "$syslog_console_file" ] \
    || die "Syslog console config is not a readable regular file: $syslog_console_file"

  syslog_console_value=""
  syslog_console_found=0
  syslog_console_line=""
  while IFS= read -r syslog_console_line || [ -n "$syslog_console_line" ]; do
    case "$syslog_console_line" in
      ""|\#*) ;;
      DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS=*)
        [ "$syslog_console_found" -eq 0 ] \
          || die "Syslog console config must contain DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS once"
        syslog_console_value="${syslog_console_line#DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS=}"
        syslog_console_found=1
        ;;
      *) die "Syslog console config contains an unsupported line" ;;
    esac
  done < "$syslog_console_file"
  [ "$syslog_console_found" -eq 1 ] \
    || die "Syslog console config must contain DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS"
  single_line "$syslog_console_value" \
    || die "Syslog console CIDRs must be a single line"
  DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS="$syslog_console_value"
}

strong_secret() {
  value="$1"
  [ "${#value}" -ge 32 ] || return 1
  lower_value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$lower_value" in
    *replace*|*change-me*|*changeme*|*password*|*example*|*default*) return 1 ;;
  esac
  case "$value" in *[!A-Za-z0-9._~+/=-]*) return 1 ;; esac
  return 0
}

single_line() {
  case "$1" in *$'\n'*|*$'\r'*) return 1 ;; esac
  return 0
}

validate_retention() {
  name="$1"
  value="$2"
  case "$value" in ""|*[!0-9]*) die "$name must be an integer number of days" ;; esac
  [ "$value" -ge 1 ] && [ "$value" -le 3650 ] || die "$name must be between 1 and 3650 days"
}

validate_distinct_tokens() {
  names=(API INGEST OPERATOR APPROVER)
  tokens=(
    "${DEFENSIVE_AI_API_TOKEN:-}"
    "${DEFENSIVE_AI_INGEST_TOKEN:-}"
    "${DEFENSIVE_AI_OPERATOR_TOKEN:-}"
    "${DEFENSIVE_AI_APPROVER_TOKEN:-}"
  )
  for i in "${!tokens[@]}"; do
    strong_secret "${tokens[$i]}" || die "DEFENSIVE_AI_${names[$i]}_TOKEN must be non-placeholder, at least 32 characters, and use the portable token alphabet"
  done
  for ((i = 0; i < ${#tokens[@]}; i++)); do
    for ((j = i + 1; j < ${#tokens[@]}; j++)); do
      [ "${tokens[$i]}" != "${tokens[$j]}" ] || die "production role tokens must be distinct"
    done
  done
}

validate_dns_name() {
  value="$1"
  [ "${#value}" -le 253 ] || return 1
  case "$value" in ""|.*|*.|*..*|*[^a-z0-9.-]*) return 1 ;; esac
  IFS='.' read -r -a labels <<< "$value"
  for label in "${labels[@]}"; do
    [ -n "$label" ] && [ "${#label}" -le 63 ] || return 1
    case "$label" in -*|*-) return 1 ;; esac
  done
  return 0
}

validate_cidr() {
  range="$1"
  case "$range" in */*) ;; *) return 1 ;; esac
  address="${range%/*}"
  prefix="${range##*/}"
  case "$prefix" in ""|*[!0-9]*) return 1 ;; esac
  # Every IPv4/IPv6 prefix of length zero is the global internet, regardless
  # of how the base address is written (for example 0.0.0.0/00).
  [ "$prefix" -ne 0 ] || return 1
  if [[ "$address" == *:* ]]; then
    [ "$prefix" -le 128 ] || return 1
    case "$address" in *[^0-9A-Fa-f:]*) return 1 ;; esac
    [ -n "$address" ] || return 1
  else
    [ "$prefix" -le 32 ] || return 1
    IFS='.' read -r -a octets <<< "$address"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for octet in "${octets[@]}"; do
      case "$octet" in ""|*[!0-9]*) return 1 ;; esac
      [ "$octet" -le 255 ] || return 1
    done
  fi
  return 0
}

cidrs_to_json() {
  value="${1//[[:space:]]/}"
  [ -n "$value" ] || return 1
  result="["
  first=1
  IFS=',' read -r -a ranges <<< "$value"
  for range in "${ranges[@]}"; do
    [ -n "$range" ] || return 1
    case "$range" in 0.0.0.0/0|::/0|*[^0-9A-Fa-f:./]*) return 1 ;; esac
    validate_cidr "$range" || return 1
    if [ "$first" -eq 0 ]; then result="$result,"; fi
    result="$result\"$range\""
    first=0
  done
  printf '%s]\n' "$result"
}

render_syslog_network_policy() {
  output="$1"
  value="${2//[[:space:]]/}"
  cidrs_to_json "$value" >/dev/null || die "cannot render invalid Syslog source CIDRs"
  {
    cat <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: syslog-collector-ingress
  namespace: defensive-ai-gateway
spec:
  podSelector:
    matchLabels:
      app: syslog-collector-vector
  policyTypes: [Ingress]
  ingress:
    - from:
EOF
    IFS=',' read -r -a ranges <<< "$value"
    for range in "${ranges[@]}"; do
      printf '        - ipBlock:\n            cidr: %s\n' "$range"
    done
    cat <<'EOF'
      ports:
        - {protocol: UDP, port: 15140}
        - {protocol: TCP, port: 15140}
        - {protocol: UDP, port: 15141}
        - {protocol: TCP, port: 15141}
        - {protocol: UDP, port: 15142}
        - {protocol: TCP, port: 15142}
        - {protocol: UDP, port: 15143}
        - {protocol: TCP, port: 15143}
        - {protocol: UDP, port: 15144}
        - {protocol: TCP, port: 15144}
EOF
  } > "$output"
}

list_contains_host() {
  list="${1//[[:space:]]/}"
  wanted="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
  IFS=',' read -r -a hosts <<< "$list"
  for candidate in "${hosts[@]}"; do
    candidate="${candidate#[}"
    candidate="${candidate%]}"
    candidate="$(printf '%s' "$candidate" | tr '[:upper:]' '[:lower:]')"
    [ "$candidate" != "$wanted" ] || return 0
  done
  return 1
}

endpoint_host() {
  endpoint="$1"
  authority="${endpoint#*://}"
  authority="${authority%%/*}"
  authority="${authority#*@}"
  if [[ "$authority" == \[* ]]; then
    host="${authority#\[}"
    host="${host%%\]*}"
  else
    host="${authority%%:*}"
  fi
  printf '%s\n' "$host"
}

validate_model_config() {
  provider="${DEFENSIVE_AI_LLM_PROVIDER:-local}"
  endpoint="${DEFENSIVE_AI_LLM_ENDPOINT:-}"
  model="${DEFENSIVE_AI_LLM_MODEL:-local-rule-analyst}"
  allowed="${DEFENSIVE_AI_LLM_ALLOWED_HOSTS:-127.0.0.1,localhost,::1}"
  single_line "$provider" && single_line "$endpoint" && single_line "$model" && single_line "$allowed" || die "LLM configuration values must be single-line"
  [ -n "$model" ] || die "DEFENSIVE_AI_LLM_MODEL is required"
  case "$provider" in
    local)
      [ -z "$endpoint" ] || die "local provider must not configure DEFENSIVE_AI_LLM_ENDPOINT"
      ;;
    ollama)
      case "$endpoint" in http://*|https://*) ;; *) die "Ollama endpoint must use http or https" ;; esac
      host="$(endpoint_host "$endpoint")"
      list_contains_host "$allowed" "$host" || die "Ollama endpoint host must be present in DEFENSIVE_AI_LLM_ALLOWED_HOSTS"
      ;;
    gateway)
      case "$endpoint" in https://*) ;; *) die "Gateway endpoint must use https" ;; esac
      host="$(endpoint_host "$endpoint")"
      list_contains_host "$allowed" "$host" || die "Gateway endpoint host must be present in DEFENSIVE_AI_LLM_ALLOWED_HOSTS"
      strong_secret "${DEFENSIVE_AI_LLM_API_KEY:-}" || die "Gateway API key must be non-placeholder and at least 32 characters"
      ;;
    *) die "DEFENSIVE_AI_LLM_PROVIDER must be local, ollama, or gateway" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

is_content_addressed_gateway_ref() {
  ref="$1"
  case "$ref" in
    *@sha256:*) digest="${ref##*@sha256:}" ;;
    *:sha256-*) digest="${ref##*:sha256-}" ;;
    *) return 1 ;;
  esac
  [ "${#digest}" -eq 64 ] || return 1
  case "$digest" in *[!0-9a-fA-F]*) return 1 ;; esac
  return 0
}

verify_image_archive() {
  tar_file="$1"
  checksum_file="$tar_file.sha256"
  ref_file="$tar_file.ref"
  [ -f "$checksum_file" ] || die "missing checksum: $checksum_file"
  [ -f "$ref_file" ] || die "missing immutable image reference: $ref_file"
  expected="$(awk '{print $1; exit}' "$checksum_file")"
  actual="$(sha256_of "$tar_file")"
  [ -n "$expected" ] && [ "$expected" = "$actual" ] || die "checksum mismatch for $tar_file"
  image_ref="$(sed -n '1p' "$ref_file")"
  case "$image_ref" in
    ""|*'@@'*|*:latest|*:dev|*[!A-Za-z0-9._/:@-]*) die "invalid or mutable image reference in $ref_file" ;;
  esac
  case "$image_ref" in
    defensive-ai-gateway:*|*/defensive-ai-gateway:*|defensive-ai-gateway@*|*/defensive-ai-gateway@*)
      is_content_addressed_gateway_ref "$image_ref" \
        || die "gateway image reference does not carry a sha256 content identity"
      ;;
  esac
  log "checksum ok: $(basename "$tar_file")"
}

import_image() {
  tar_file="$1"
  verify_image_archive "$tar_file"
  log "importing image: $(basename "$tar_file")"
  if command -v k3s >/dev/null 2>&1; then
    sudo k3s ctr images import "$tar_file"
  elif command -v ctr >/dev/null 2>&1; then
    sudo ctr -n k8s.io images import "$tar_file"
  else
    die "neither k3s nor ctr was found; cannot import image tar"
  fi
}

manifest_image() {
  awk '$1 == "image:" {gsub(/"/, "", $2); print $2; exit}' "$1"
}

require_runtime_image() {
  image_ref="$1"
  if [[ "$image_ref" != */* ]]; then
    normalized_ref="docker.io/library/$image_ref"
  elif [[ "${image_ref%%/*}" != *.* && "${image_ref%%/*}" != *:* && "${image_ref%%/*}" != "localhost" ]]; then
    normalized_ref="docker.io/$image_ref"
  else
    normalized_ref="$image_ref"
  fi
  if command -v k3s >/dev/null 2>&1; then
    if sudo k3s ctr images list -q \
      | awk -v raw="$image_ref" -v normalized="$normalized_ref" '$0 == raw || $0 == normalized {found=1} END {exit !found}'; then
      return 0
    fi
  elif command -v ctr >/dev/null 2>&1; then
    if sudo ctr -n k8s.io images list -q \
      | awk -v raw="$image_ref" -v normalized="$normalized_ref" '$0 == raw || $0 == normalized {found=1} END {exit !found}'; then
      return 0
    fi
  else
    die "neither k3s nor ctr was found; cannot verify rollback image"
  fi
  die "rollback image is no longer present on this air-gapped node: $image_ref"
}

backup_data() {
  configmap_name="$1"
  key="$2"
  kubectl -n "$NAMESPACE" get configmap "$configmap_name" \
    -o go-template="{{index .data \"$key\"}}"
}

restore_resource_spec() {
  backup_meta="$1"
  kind="$2"
  name="$3"
  key="$4"
  spec="$(backup_data "$backup_meta" "$key")"
  [ -n "$spec" ] || die "rollback point is missing $key"
  kubectl -n "$NAMESPACE" get "$kind" "$name" >/dev/null 2>&1 \
    || die "cannot restore missing $kind/$name"
  kubectl -n "$NAMESPACE" patch "$kind" "$name" --type=json \
    -p="[{\"op\":\"replace\",\"path\":\"/spec\",\"value\":$spec}]"
}

restore_gateway_workload_contract() {
  backup_meta="$1"
  restore_resource_spec "$backup_meta" service defensive-ai-gateway gateway-service-spec.json
  restore_resource_spec "$backup_meta" deployment defensive-ai-gateway gateway-deployment-spec.json
}

wait_for_pods_deleted() {
  selector="$1"
  pods="$(kubectl -n "$NAMESPACE" get pod -l "$selector" -o name 2>/dev/null || true)"
  [ -z "$pods" ] || kubectl -n "$NAMESPACE" wait \
    --for=delete pod -l "$selector" --timeout=120s
}

copy_runtime_secret() {
  source_name="$1"
  target_name="$2"
  SECRET_COPY_FILE="$(mktemp "${TMPDIR:-/tmp}/defensive-ai-secret-copy.XXXXXX")"
  chmod 600 "$SECRET_COPY_FILE"
  secret_keys=(
    DEFENSIVE_AI_API_TOKEN
    DEFENSIVE_AI_INGEST_TOKEN
    DEFENSIVE_AI_OPERATOR_TOKEN
    DEFENSIVE_AI_APPROVER_TOKEN
    DEFENSIVE_AI_AUTH_LOOPBACK
    DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN
    DEFENSIVE_AI_DEMO_MODE
    DEFENSIVE_AI_APPROVAL_QUORUM
    DEFENSIVE_AI_LLM_PROVIDER
    DEFENSIVE_AI_LLM_ENDPOINT
    DEFENSIVE_AI_LLM_MODEL
    DEFENSIVE_AI_LLM_ALLOWED_HOSTS
    DEFENSIVE_AI_LLM_API_KEY
    DEFENSIVE_AI_DATA_RETENTION_DAYS
    DEFENSIVE_AI_AUDIT_RETENTION_DAYS
    DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS
    DEFENSIVE_AI_EMBEDDED_SYSLOG
  )
  for key in "${secret_keys[@]}"; do
    present="$(kubectl -n "$NAMESPACE" get secret "$source_name" -o go-template="{{if index .data \"$key\"}}1{{end}}")"
    [ "$present" = "1" ] || continue
    value="$(kubectl -n "$NAMESPACE" get secret "$source_name" -o go-template="{{index .data \"$key\" | base64decode}}")"
    single_line "$value" || die "stored Secret contains a multiline value: $key"
    printf '%s=%s\n' "$key" "$value" >> "$SECRET_COPY_FILE"
  done
  [ -s "$SECRET_COPY_FILE" ] || die "runtime Secret has no restorable values"
  kubectl -n "$NAMESPACE" create secret generic "$target_name" \
    --from-env-file="$SECRET_COPY_FILE" --dry-run=client -o yaml | kubectl apply -f -
  rm -f "$SECRET_COPY_FILE"
  SECRET_COPY_FILE=""
}

validate_rendered_manifests() {
  gateway_manifest="$ROOT_DIR/deploy/k3s/gateway.yaml"
  gateway_ref="$(manifest_image "$gateway_manifest")"
  case "$gateway_ref" in
    ""|*'@@'*|*:latest|*:dev) die "gateway manifest does not contain an immutable packaged image" ;;
  esac
  is_content_addressed_gateway_ref "$gateway_ref" \
    || die "gateway manifest image must contain its sha256 content identity"
  if [ "$WITH_SYSLOG" -eq 1 ]; then
    vector_ref="$(manifest_image "$ROOT_DIR/deploy/k3s/syslog-collector-vector.yaml")"
    case "$vector_ref" in
      ""|*'@@'*|*:latest|*:dev) die "--with-syslog requires a bundle containing a digest-pinned Vector image" ;;
    esac
  fi
}

prune_backups() {
  keep="$1"
  backups="$(kubectl -n "$NAMESPACE" get configmap -l defensive-ai-gateway-backup=true \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | awk '/^defensive-ai-gateway-backup-/' | sort || true)"
  [ -n "$backups" ] || return
  # Backup names start with an UTC timestamp, so lexical order is oldest first.
  set -- $backups
  count=$#
  while [ "$count" -gt "$keep" ]; do
    configmap_name="$1"
    shift
    count=$((count - 1))
    old_id="${configmap_name#defensive-ai-gateway-backup-}"
    log "pruning old rollback point: $old_id"
    kubectl -n "$NAMESPACE" exec deployment/defensive-ai-gateway -- \
      python -c 'import os,sys; p=f"/data/backups/{sys.argv[1]}.db"; os.path.exists(p) and os.remove(p)' \
      "$old_id"
    kubectl -n "$NAMESPACE" delete configmap "$configmap_name" --ignore-not-found >/dev/null
    kubectl -n "$NAMESPACE" delete configmap "defensive-ai-syslog-backup-$old_id" --ignore-not-found >/dev/null
    kubectl -n "$NAMESPACE" delete secret "defensive-ai-gateway-secrets-backup-$old_id" --ignore-not-found >/dev/null
  done
}

backup_database() {
  if [ "$SKIP_BACKUP" -eq 1 ]; then
    log "WARNING: pre-upgrade database backup explicitly skipped"
    return
  fi
  if ! kubectl -n "$NAMESPACE" get deployment defensive-ai-gateway >/dev/null 2>&1; then
    return
  fi
  prune_backups "$((BACKUP_RETENTION_COUNT - 1))"
  PREVIOUS_IMAGE="$(kubectl -n "$NAMESPACE" get deployment defensive-ai-gateway -o jsonpath='{.spec.template.spec.containers[?(@.name=="gateway")].image}')"
  [ -n "$PREVIOUS_IMAGE" ] || die "cannot determine current gateway image before upgrade"
  BACKUP_ID="$(date -u '+%Y%m%dt%H%M%Sz' | tr '[:upper:]' '[:lower:]')-$(printf '%04d' "$((RANDOM % 10000))")"
  log "creating SQLite backup: $BACKUP_ID"
  kubectl -n "$NAMESPACE" exec deployment/defensive-ai-gateway -- \
    python -c 'import os; p="/data/gateway.db"; size=os.path.getsize(p) if os.path.exists(p) else 0; free=os.statvfs("/data").f_bavail*os.statvfs("/data").f_frsize; required=max(size+size//5,67_108_864); assert free>=required, f"insufficient backup space: free={free}, required={required}"'
  kubectl -n "$NAMESPACE" exec deployment/defensive-ai-gateway -- \
    python -c 'import os,sqlite3,sys; bid=sys.argv[1]; os.makedirs("/data/backups", exist_ok=True); src=sqlite3.connect("/data/gateway.db"); dst=sqlite3.connect(f"/data/backups/{bid}.db"); src.backup(dst); dst.close(); src.close(); os.chmod(f"/data/backups/{bid}.db", 0o600)' \
    "$BACKUP_ID"

  # Store the complete workload/service specs. Restoring only the old image
  # would leave it running with new probes, resources or pod security settings.
  WORKLOAD_SPEC_DIR="$(mktemp -d "${TMPDIR:-/tmp}/defensive-ai-workload-spec.XXXXXX")"
  kubectl -n "$NAMESPACE" get deployment defensive-ai-gateway \
    -o jsonpath='{.spec}' > "$WORKLOAD_SPEC_DIR/gateway-deployment-spec.json"
  kubectl -n "$NAMESPACE" get service defensive-ai-gateway \
    -o jsonpath='{.spec}' > "$WORKLOAD_SPEC_DIR/gateway-service-spec.json"
  [ -s "$WORKLOAD_SPEC_DIR/gateway-deployment-spec.json" ] \
    && [ -s "$WORKLOAD_SPEC_DIR/gateway-service-spec.json" ] \
    || die "cannot capture the current Gateway workload contract"

  current_hostport="$(kubectl -n "$NAMESPACE" get deployment defensive-ai-gateway -o jsonpath='{.spec.template.spec.containers[?(@.name=="gateway")].ports[?(@.name=="http")].hostPort}' 2>/dev/null || true)"
  exposure_mode="cluster"
  public_host=""
  tls_secret=""
  source_cidrs=""
  if [ -n "$current_hostport" ]; then
    exposure_mode="demo"
  elif kubectl -n "$NAMESPACE" get ingress defensive-ai-gateway >/dev/null 2>&1; then
    exposure_mode="production"
    public_host="$(kubectl -n "$NAMESPACE" get ingress defensive-ai-gateway -o jsonpath='{.spec.rules[0].host}')"
    tls_secret="$(kubectl -n "$NAMESPACE" get ingress defensive-ai-gateway -o jsonpath='{.spec.tls[0].secretName}')"
    source_cidrs="$(kubectl -n "$NAMESPACE" get ingress defensive-ai-gateway -o go-template='{{index .metadata.annotations "nginx.ingress.kubernetes.io/whitelist-source-range"}}')"
    validate_dns_name "$public_host" || die "current production Ingress host cannot be backed up safely"
    validate_dns_name "$tls_secret" || die "current production TLS Secret name cannot be backed up safely"
    cidrs_to_json "$source_cidrs" >/dev/null || die "current production source allowlist cannot be backed up safely"
  fi

  vector_present=0
  vector_image=""
  vector_source_cidrs=""
  vector_network_policy=0
  if kubectl -n "$NAMESPACE" get deployment syslog-collector-vector >/dev/null 2>&1; then
    vector_present=1
    vector_image="$(kubectl -n "$NAMESPACE" get deployment syslog-collector-vector -o jsonpath='{.spec.template.spec.containers[?(@.name=="vector")].image}')"
    [ -n "$vector_image" ] || die "cannot determine current Vector image"
    kubectl -n "$NAMESPACE" get deployment syslog-collector-vector \
      -o jsonpath='{.spec}' > "$WORKLOAD_SPEC_DIR/vector-deployment-spec.json"
    kubectl -n "$NAMESPACE" get service syslog-collector \
      -o jsonpath='{.spec}' > "$WORKLOAD_SPEC_DIR/vector-service-spec.json"
    [ -s "$WORKLOAD_SPEC_DIR/vector-deployment-spec.json" ] \
      && [ -s "$WORKLOAD_SPEC_DIR/vector-service-spec.json" ] \
      || die "cannot capture the current Vector workload contract"
    vector_source_cidrs="$(kubectl -n "$NAMESPACE" get service syslog-collector -o jsonpath='{range .spec.loadBalancerSourceRanges[*]}{.}{","}{end}' 2>/dev/null || true)"
    vector_source_cidrs="${vector_source_cidrs%,}"
    cidrs_to_json "$vector_source_cidrs" >/dev/null || die "current Syslog source allowlist cannot be backed up safely"
    if kubectl -n "$NAMESPACE" get networkpolicy syslog-collector-ingress >/dev/null 2>&1; then
      vector_network_policy=1
    fi
    VECTOR_COPY_FILE="$(mktemp "${TMPDIR:-/tmp}/defensive-ai-vector.XXXXXX")"
    kubectl -n "$NAMESPACE" get configmap syslog-collector-vector-config \
      -o jsonpath='{.data.vector\.toml}' > "$VECTOR_COPY_FILE"
    [ -s "$VECTOR_COPY_FILE" ] || die "current Vector config is empty"
    kubectl -n "$NAMESPACE" create configmap "defensive-ai-syslog-backup-$BACKUP_ID" \
      --from-file=vector.toml="$VECTOR_COPY_FILE" --dry-run=client -o yaml | kubectl apply -f -
    rm -f "$VECTOR_COPY_FILE"
    VECTOR_COPY_FILE=""
  fi
  copy_runtime_secret defensive-ai-gateway-secrets "defensive-ai-gateway-secrets-backup-$BACKUP_ID"
  kubectl -n "$NAMESPACE" label secret "defensive-ai-gateway-secrets-backup-$BACKUP_ID" \
    defensive-ai-gateway-backup=true --overwrite >/dev/null
  workload_spec_args=(
    --from-file="gateway-deployment-spec.json=$WORKLOAD_SPEC_DIR/gateway-deployment-spec.json"
    --from-file="gateway-service-spec.json=$WORKLOAD_SPEC_DIR/gateway-service-spec.json"
  )
  if [ "$vector_present" = "1" ]; then
    workload_spec_args+=(
      --from-file="vector-deployment-spec.json=$WORKLOAD_SPEC_DIR/vector-deployment-spec.json"
      --from-file="vector-service-spec.json=$WORKLOAD_SPEC_DIR/vector-service-spec.json"
    )
  fi
  kubectl -n "$NAMESPACE" create configmap "defensive-ai-gateway-backup-$BACKUP_ID" \
    "${workload_spec_args[@]}" \
    --from-literal="image_ref=$PREVIOUS_IMAGE" \
    --from-literal="database_file=/data/backups/$BACKUP_ID.db" \
    --from-literal="exposure_mode=$exposure_mode" \
    --from-literal="public_host=$public_host" \
    --from-literal="tls_secret=$tls_secret" \
    --from-literal="source_cidrs=$source_cidrs" \
    --from-literal="vector_present=$vector_present" \
    --from-literal="vector_image=$vector_image" \
    --from-literal="vector_source_cidrs=$vector_source_cidrs" \
    --from-literal="vector_network_policy=$vector_network_policy" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "$NAMESPACE" label configmap "defensive-ai-gateway-backup-$BACKUP_ID" \
    defensive-ai-gateway-backup=true --overwrite >/dev/null
  rm -rf "$WORKLOAD_SPEC_DIR"
  WORKLOAD_SPEC_DIR=""
  BACKUP_COMPLETE=1
}

restore_vector_contract() {
  backup_id="$1"
  backup_meta="defensive-ai-gateway-backup-$backup_id"
  vector_present="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.vector_present}')"
  if [ "$vector_present" != "1" ]; then
    kubectl -n "$NAMESPACE" delete deployment syslog-collector-vector --ignore-not-found
    kubectl -n "$NAMESPACE" delete service syslog-collector --ignore-not-found
    kubectl -n "$NAMESPACE" delete configmap syslog-collector-vector-config --ignore-not-found
    kubectl -n "$NAMESPACE" delete networkpolicy syslog-collector-ingress --ignore-not-found
    return
  fi
  vector_image="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.vector_image}')"
  vector_source_cidrs="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.vector_source_cidrs}')"
  vector_network_policy="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.vector_network_policy}' 2>/dev/null || true)"
  case "$vector_image" in ""|*[!A-Za-z0-9._/:@-]*) die "backup Vector image is invalid" ;; esac
  vector_cidrs_json="$(cidrs_to_json "$vector_source_cidrs")" || die "backup Vector source CIDRs are invalid"
  if ! kubectl -n "$NAMESPACE" get deployment syslog-collector-vector >/dev/null 2>&1 \
    || ! kubectl -n "$NAMESPACE" get service syslog-collector >/dev/null 2>&1; then
    vector_manifest="$ROOT_DIR/deploy/k3s/syslog-collector-vector.yaml"
    vector_manifest_image="$(manifest_image "$vector_manifest")"
    case "$vector_manifest_image" in
      ""|*'@@'*|*:latest|*:dev) die "cannot recreate the previous Syslog collector from a mutable bundle manifest" ;;
    esac
    VECTOR_COPY_FILE="$(mktemp "${TMPDIR:-/tmp}/defensive-ai-vector-recreate.XXXXXX")"
    sed "s|\"@@SYSLOG_SOURCE_CIDRS_JSON@@\"|$vector_cidrs_json|g" \
      "$vector_manifest" > "$VECTOR_COPY_FILE"
    kubectl apply -f "$VECTOR_COPY_FILE"
    rm -f "$VECTOR_COPY_FILE"
    VECTOR_COPY_FILE=""
  fi
  kubectl -n "$NAMESPACE" scale deployment syslog-collector-vector --replicas=0
  wait_for_pods_deleted app=syslog-collector-vector
  VECTOR_COPY_FILE="$(mktemp "${TMPDIR:-/tmp}/defensive-ai-vector-restore.XXXXXX")"
  kubectl -n "$NAMESPACE" get configmap "defensive-ai-syslog-backup-$backup_id" \
    -o jsonpath='{.data.vector\.toml}' > "$VECTOR_COPY_FILE"
  [ -s "$VECTOR_COPY_FILE" ] || die "backup Vector config is empty"
  kubectl -n "$NAMESPACE" create configmap syslog-collector-vector-config \
    --from-file=vector.toml="$VECTOR_COPY_FILE" --dry-run=client -o yaml | kubectl apply -f -
  rm -f "$VECTOR_COPY_FILE"
  VECTOR_COPY_FILE=""
  restore_resource_spec "$backup_meta" service syslog-collector vector-service-spec.json
  if [ "$vector_network_policy" = "1" ]; then
    SYSLOG_POLICY_FILE="$(mktemp "${TMPDIR:-/tmp}/defensive-ai-syslog-policy.XXXXXX")"
    render_syslog_network_policy "$SYSLOG_POLICY_FILE" "$vector_source_cidrs"
    kubectl apply -f "$SYSLOG_POLICY_FILE"
    rm -f "$SYSLOG_POLICY_FILE"
    SYSLOG_POLICY_FILE=""
  else
    kubectl -n "$NAMESPACE" delete networkpolicy syslog-collector-ingress --ignore-not-found
  fi
  restore_resource_spec "$backup_meta" deployment syslog-collector-vector vector-deployment-spec.json
  kubectl -n "$NAMESPACE" rollout status deployment/syslog-collector-vector --timeout=180s
}

restore_exposure_contract() {
  exposure_mode="$1"
  public_host="$2"
  tls_secret="$3"
  source_cidrs="$4"
  if [ "$exposure_mode" = "demo" ]; then
    kubectl -n "$NAMESPACE" delete ingress defensive-ai-gateway --ignore-not-found
    kubectl -n "$NAMESPACE" delete networkpolicy defensive-ai-gateway-ingress --ignore-not-found
    kubectl -n "$NAMESPACE" delete middleware defensive-ai-gateway-source-allowlist --ignore-not-found 2>/dev/null || true
    kubectl -n "$NAMESPACE" patch deployment defensive-ai-gateway --type=strategic \
      --patch-file "$ROOT_DIR/deploy/k3s/demo-exposure-patch.yaml"
    return
  fi
  kubectl -n "$NAMESPACE" patch deployment defensive-ai-gateway --type=json \
    -p='[{"op":"remove","path":"/spec/template/spec/containers/0/ports/0/hostPort"}]' 2>/dev/null || true
  if [ "$exposure_mode" = "production" ]; then
    validate_dns_name "$public_host" || die "backup public host is invalid"
    validate_dns_name "$tls_secret" || die "backup TLS Secret name is invalid"
    restored_cidrs_json="$(cidrs_to_json "$source_cidrs")" || die "backup source CIDRs are invalid"
    restore_exposure="$(mktemp "${TMPDIR:-/tmp}/defensive-ai-exposure.XXXXXX")"
    sed \
      -e "s|@@PUBLIC_HOST@@|$public_host|g" \
      -e "s|@@TLS_SECRET@@|$tls_secret|g" \
      -e "s|@@SOURCE_CIDRS_CSV@@|${source_cidrs//[[:space:]]/}|g" \
      -e "s|\"@@SOURCE_CIDRS_JSON@@\"|$restored_cidrs_json|g" \
      "$ROOT_DIR/deploy/k3s/production-exposure.yaml" > "$restore_exposure"
    kubectl apply -f "$restore_exposure"
    rm -f "$restore_exposure"
  else
    kubectl -n "$NAMESPACE" delete ingress defensive-ai-gateway --ignore-not-found
    kubectl -n "$NAMESPACE" delete networkpolicy defensive-ai-gateway-ingress --ignore-not-found
    kubectl -n "$NAMESPACE" delete middleware defensive-ai-gateway-source-allowlist --ignore-not-found 2>/dev/null || true
  fi
}

restore_database() {
  backup_id="$1"
  previous_image="$2"
  case "$backup_id" in *[!a-z0-9-]*|"") die "invalid backup id: $backup_id" ;; esac
  case "$previous_image" in *[!A-Za-z0-9._/:@-]*|"") die "invalid rollback image" ;; esac
  backup_meta="defensive-ai-gateway-backup-$backup_id"
  backup_secret="defensive-ai-gateway-secrets-backup-$backup_id"
  kubectl -n "$NAMESPACE" get secret "$backup_secret" >/dev/null 2>&1 || die "backup Secret not found: $backup_secret"
  exposure_mode="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.exposure_mode}')"
  case "$exposure_mode" in demo|production|cluster) ;; *) die "backup exposure metadata is invalid" ;; esac
  public_host="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.public_host}')"
  tls_secret="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.tls_secret}')"
  source_cidrs="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.source_cidrs}')"
  vector_present="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.vector_present}')"
  require_runtime_image "$previous_image"
  if [ "$vector_present" = "1" ]; then
    rollback_vector_image="$(kubectl -n "$NAMESPACE" get configmap "$backup_meta" -o jsonpath='{.data.vector_image}')"
    case "$rollback_vector_image" in ""|*[!A-Za-z0-9._/:@-]*) die "backup Vector image is invalid" ;; esac
    require_runtime_image "$rollback_vector_image"
  fi
  restore_pod="defensive-ai-gateway-restore-$backup_id"
  restore_pod="${restore_pod:0:63}"
  log "restoring database backup $backup_id with image $previous_image"
  kubectl -n "$NAMESPACE" scale deployment defensive-ai-gateway --replicas=0
  if ! wait_for_pods_deleted app=defensive-ai-gateway; then
    kubectl -n "$NAMESPACE" scale deployment defensive-ai-gateway --replicas=1 || true
    die "gateway Pod did not stop; database restore was not started"
  fi
  kubectl -n "$NAMESPACE" delete pod "$restore_pod" --ignore-not-found >/dev/null
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $restore_pod
  namespace: $NAMESPACE
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: restore
      image: "$previous_image"
      imagePullPolicy: Never
      command: ["python", "-c"]
      args:
        - "import os,shutil,sys; bid=sys.argv[1]; src=f'/data/backups/{bid}.db'; dst='/data/gateway.db'; tmp=dst+'.restore'; assert os.path.isfile(src), src; shutil.copy2(src,tmp); os.chmod(tmp,0o600); [os.remove(p) for p in (dst+'-wal',dst+'-shm') if os.path.exists(p)]; os.replace(tmp,dst)"
        - "$backup_id"
      volumeMounts:
        - {name: data, mountPath: /data}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
  volumes:
    - name: data
      persistentVolumeClaim: {claimName: defensive-ai-gateway-data}
EOF
  for _ in $(seq 1 60); do
    phase="$(kubectl -n "$NAMESPACE" get pod "$restore_pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [ "$phase" != "Succeeded" ] || break
    [ "$phase" != "Failed" ] || break
    sleep 2
  done
  if [ "${phase:-}" != "Succeeded" ]; then
    kubectl -n "$NAMESPACE" delete pod "$restore_pod" --wait=true --ignore-not-found >/dev/null
    copy_runtime_secret "$backup_secret" defensive-ai-gateway-secrets
    restore_exposure_contract "$exposure_mode" "$public_host" "$tls_secret" "$source_cidrs"
    restore_gateway_workload_contract "$backup_meta"
    kubectl -n "$NAMESPACE" rollout status deployment/defensive-ai-gateway --timeout=180s
    restore_vector_contract "$backup_id"
    die "database restore pod ${phase:-timed out}; previous runtime contract was resumed with the original database"
  fi
  kubectl -n "$NAMESPACE" delete pod "$restore_pod" --wait=true >/dev/null
  copy_runtime_secret "$backup_secret" defensive-ai-gateway-secrets
  restore_exposure_contract "$exposure_mode" "$public_host" "$tls_secret" "$source_cidrs"
  restore_gateway_workload_contract "$backup_meta"
  kubectl -n "$NAMESPACE" rollout status deployment/defensive-ai-gateway --timeout=180s
  # The previous contract decides whether Vector must exist. This also removes
  # a newly introduced collector when the rollback point did not contain one.
  restore_vector_contract "$backup_id"
}

rollback_after_error() {
  status=$?
  trap - ERR
  if [ -n "$BACKUP_ID" ] && [ -n "$PREVIOUS_IMAGE" ]; then
    log "deployment failed; rolling back image and database to $BACKUP_ID"
    # Run rollback as a fresh strict shell. Calling the function directly on the
    # left side of `||` disables Bash errexit throughout the function body.
    if bash "$0" --rollback "$BACKUP_ID"; then
      log "automatic rollback completed: $BACKUP_ID"
    else
      log "CRITICAL: automatic rollback failed; preserve backup $BACKUP_ID and investigate"
    fi
  fi
  exit "$status"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --image-dir) [ "$#" -ge 2 ] || die "--image-dir requires a value"; IMAGE_DIR="$2"; shift 2 ;;
    --with-syslog) WITH_SYSLOG=1; shift ;;
    --syslog-console-config) [ "$#" -ge 2 ] || die "--syslog-console-config requires a file"; SYSLOG_CONSOLE_CONFIG="$2"; shift 2 ;;
    --demo-mode|--allow-empty-token) DEMO_MODE=1; shift ;;
    --require-token) shift ;;
    --skip-backup) SKIP_BACKUP=1; shift ;;
    --rollback) [ "$#" -ge 2 ] || die "--rollback requires a backup id"; ROLLBACK_ID="$2"; shift 2 ;;
    --preflight-only) PREFLIGHT_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

if [ -n "$ROLLBACK_ID" ]; then
  command -v kubectl >/dev/null 2>&1 || die "kubectl not found"
  image_ref="$(kubectl -n "$NAMESPACE" get configmap "defensive-ai-gateway-backup-$ROLLBACK_ID" -o jsonpath='{.data.image_ref}')" || die "backup metadata not found: $ROLLBACK_ID"
  restore_database "$ROLLBACK_ID" "$image_ref"
  log "rollback complete: $ROLLBACK_ID"
  exit 0
fi

load_environment
if [ -n "$SYSLOG_CONSOLE_CONFIG" ]; then
  [ "$WITH_SYSLOG" -eq 1 ] || die "--syslog-console-config requires --with-syslog"
  [ "$DEMO_MODE" -eq 0 ] || die "--syslog-console-config is not available in demo mode"
  load_syslog_console_config "$SYSLOG_CONSOLE_CONFIG"
fi
if [ -z "$IMAGE_DIR" ]; then
  IMAGE_DIR="${K3S_IMAGE_DIR:-$ROOT_DIR/images}"
fi
validate_model_config
validate_retention DEFENSIVE_AI_DATA_RETENTION_DAYS "${DEFENSIVE_AI_DATA_RETENTION_DAYS:-90}"
validate_retention DEFENSIVE_AI_AUDIT_RETENTION_DAYS "${DEFENSIVE_AI_AUDIT_RETENTION_DAYS:-365}"
validate_retention DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS "${DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS:-365}"
BACKUP_RETENTION_COUNT="${DEFENSIVE_AI_BACKUP_RETENTION_COUNT:-5}"
case "$BACKUP_RETENTION_COUNT" in ""|*[!0-9]*) die "DEFENSIVE_AI_BACKUP_RETENTION_COUNT must be an integer" ;; esac
[ "$BACKUP_RETENTION_COUNT" -ge 1 ] && [ "$BACKUP_RETENTION_COUNT" -le 20 ] || die "DEFENSIVE_AI_BACKUP_RETENTION_COUNT must be between 1 and 20"

if [ "$DEMO_MODE" -eq 0 ]; then
  validate_distinct_tokens
  validate_dns_name "${DEFENSIVE_AI_PUBLIC_HOST:-}" || die "DEFENSIVE_AI_PUBLIC_HOST must be a valid DNS name"
  validate_dns_name "${DEFENSIVE_AI_TLS_SECRET:-}" || die "DEFENSIVE_AI_TLS_SECRET must be a valid Kubernetes Secret name"
  SOURCE_CIDRS_JSON="$(cidrs_to_json "${DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS:-}")" || die "DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS must contain restricted CIDRs"
  if [ "$WITH_SYSLOG" -eq 1 ]; then
    SYSLOG_SOURCE_CIDRS_JSON="$(cidrs_to_json "${DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS:-}")" || die "DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS must contain restricted CIDRs"
  fi
else
  SOURCE_CIDRS_JSON="[]"
  SYSLOG_SOURCE_CIDRS_JSON='["127.0.0.1/32"]'
  log "WARNING: demo mode enables unauthenticated hostPort HTTP; never use it in production"
fi

[ "$PREFLIGHT_ONLY" -eq 0 ] || { log "preflight passed"; exit 0; }

command -v kubectl >/dev/null 2>&1 || die "kubectl not found"

validate_rendered_manifests
[ -d "$IMAGE_DIR" ] || die "image directory not found: $IMAGE_DIR"
found_tar=0
for tar_file in "$IMAGE_DIR"/*.tar; do
  [ -f "$tar_file" ] || continue
  found_tar=1
  import_image "$tar_file"
done
[ "$found_tar" -eq 1 ] || die "no image tar found in $IMAGE_DIR"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
if [ "$DEMO_MODE" -eq 0 ]; then
  tls_type="$(kubectl -n "$NAMESPACE" get secret "$DEFENSIVE_AI_TLS_SECRET" -o jsonpath='{.type}' 2>/dev/null || true)"
  tls_crt="$(kubectl -n "$NAMESPACE" get secret "$DEFENSIVE_AI_TLS_SECRET" -o jsonpath='{.data.tls\.crt}' 2>/dev/null || true)"
  tls_key="$(kubectl -n "$NAMESPACE" get secret "$DEFENSIVE_AI_TLS_SECRET" -o jsonpath='{.data.tls\.key}' 2>/dev/null || true)"
  [ "$tls_type" = "kubernetes.io/tls" ] && [ -n "$tls_crt" ] && [ -n "$tls_key" ] || die "valid kubernetes.io/tls Secret not found: $NAMESPACE/$DEFENSIVE_AI_TLS_SECRET"
  kubectl api-resources --api-group=traefik.io 2>/dev/null | grep -q '^middlewares' || die "Traefik Middleware CRD is required for fail-closed source allowlisting"
fi

backup_database
trap rollback_after_error ERR

# Remove the opposite exposure before changing authentication values, so mode
# transitions never create a tokenless public window or a plaintext prod window.
if kubectl -n "$NAMESPACE" get deployment defensive-ai-gateway >/dev/null 2>&1; then
  if [ "$DEMO_MODE" -eq 1 ]; then
    kubectl -n "$NAMESPACE" delete ingress defensive-ai-gateway --ignore-not-found
    kubectl -n "$NAMESPACE" delete networkpolicy defensive-ai-gateway-ingress --ignore-not-found
    kubectl -n "$NAMESPACE" delete middleware defensive-ai-gateway-source-allowlist --ignore-not-found 2>/dev/null || true
  else
    kubectl -n "$NAMESPACE" patch deployment defensive-ai-gateway --type=json \
      -p='[{"op":"remove","path":"/spec/template/spec/containers/0/ports/0/hostPort"}]' 2>/dev/null || true
  fi
fi

SECRET_FILE="$(mktemp "${TMPDIR:-/tmp}/defensive-ai-secret.XXXXXX")"
chmod 600 "$SECRET_FILE"
cat > "$SECRET_FILE" <<EOF
DEFENSIVE_AI_API_TOKEN=${DEFENSIVE_AI_API_TOKEN:-}
DEFENSIVE_AI_INGEST_TOKEN=${DEFENSIVE_AI_INGEST_TOKEN:-}
DEFENSIVE_AI_OPERATOR_TOKEN=${DEFENSIVE_AI_OPERATOR_TOKEN:-}
DEFENSIVE_AI_APPROVER_TOKEN=${DEFENSIVE_AI_APPROVER_TOKEN:-}
DEFENSIVE_AI_AUTH_LOOPBACK=$([ "$DEMO_MODE" -eq 1 ] && printf 1 || printf 0)
DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN=$([ "$DEMO_MODE" -eq 1 ] && printf 0 || printf 1)
DEFENSIVE_AI_DEMO_MODE=$([ "$DEMO_MODE" -eq 1 ] && printf 1 || printf 0)
DEFENSIVE_AI_APPROVAL_QUORUM=$([ "$DEMO_MODE" -eq 1 ] && printf 1 || printf 2)
DEFENSIVE_AI_LLM_PROVIDER=${DEFENSIVE_AI_LLM_PROVIDER:-local}
DEFENSIVE_AI_LLM_ENDPOINT=${DEFENSIVE_AI_LLM_ENDPOINT:-}
DEFENSIVE_AI_LLM_MODEL=${DEFENSIVE_AI_LLM_MODEL:-local-rule-analyst}
DEFENSIVE_AI_LLM_ALLOWED_HOSTS=${DEFENSIVE_AI_LLM_ALLOWED_HOSTS:-127.0.0.1,localhost,::1}
DEFENSIVE_AI_LLM_API_KEY=${DEFENSIVE_AI_LLM_API_KEY:-}
DEFENSIVE_AI_DATA_RETENTION_DAYS=${DEFENSIVE_AI_DATA_RETENTION_DAYS:-90}
DEFENSIVE_AI_AUDIT_RETENTION_DAYS=${DEFENSIVE_AI_AUDIT_RETENTION_DAYS:-365}
DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS=${DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS:-365}
DEFENSIVE_AI_EMBEDDED_SYSLOG=0
EOF
kubectl -n "$NAMESPACE" create secret generic defensive-ai-gateway-secrets \
  --from-env-file="$SECRET_FILE" --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f "$ROOT_DIR/deploy/k3s/gateway.yaml"
RENDER_DIR="$(mktemp -d "${TMPDIR:-/tmp}/defensive-ai-k3s.XXXXXX")"

if [ "$DEMO_MODE" -eq 1 ]; then
  kubectl -n "$NAMESPACE" patch deployment defensive-ai-gateway --type=strategic \
    --patch-file "$ROOT_DIR/deploy/k3s/demo-exposure-patch.yaml"
else
  kubectl -n "$NAMESPACE" patch deployment defensive-ai-gateway --type=json \
    -p='[{"op":"remove","path":"/spec/template/spec/containers/0/ports/0/hostPort"}]' 2>/dev/null || true
  sed \
    -e "s|@@PUBLIC_HOST@@|$DEFENSIVE_AI_PUBLIC_HOST|g" \
    -e "s|@@TLS_SECRET@@|$DEFENSIVE_AI_TLS_SECRET|g" \
    -e "s|@@SOURCE_CIDRS_CSV@@|${DEFENSIVE_AI_ALLOWED_SOURCE_CIDRS//[[:space:]]/}|g" \
    -e "s|\"@@SOURCE_CIDRS_JSON@@\"|$SOURCE_CIDRS_JSON|g" \
    "$ROOT_DIR/deploy/k3s/production-exposure.yaml" > "$RENDER_DIR/production-exposure.yaml"
  kubectl apply -f "$RENDER_DIR/production-exposure.yaml"
fi

if [ "$WITH_SYSLOG" -eq 1 ]; then
  sed "s|\"@@SYSLOG_SOURCE_CIDRS_JSON@@\"|$SYSLOG_SOURCE_CIDRS_JSON|g" \
    "$ROOT_DIR/deploy/k3s/syslog-collector-vector.yaml" > "$RENDER_DIR/syslog-collector-vector.yaml"
  kubectl apply -f "$RENDER_DIR/syslog-collector-vector.yaml"
  if [ "$DEMO_MODE" -eq 0 ]; then
    render_syslog_network_policy \
      "$RENDER_DIR/syslog-collector-network-policy.yaml" \
      "$DEFENSIVE_AI_SYSLOG_SOURCE_CIDRS"
    kubectl apply -f "$RENDER_DIR/syslog-collector-network-policy.yaml"
  else
    kubectl -n "$NAMESPACE" delete networkpolicy syslog-collector-ingress --ignore-not-found
  fi
fi

# Secret changes are part of the pod template revision even when the image is unchanged.
kubectl -n "$NAMESPACE" rollout restart deployment/defensive-ai-gateway
kubectl -n "$NAMESPACE" rollout status deployment/defensive-ai-gateway --timeout=180s
if kubectl -n "$NAMESPACE" get deployment syslog-collector-vector >/dev/null 2>&1; then
  kubectl -n "$NAMESPACE" rollout restart deployment/syslog-collector-vector
  kubectl -n "$NAMESPACE" rollout status deployment/syslog-collector-vector --timeout=180s
fi

trap - ERR
log "deployment complete"
if [ "$DEMO_MODE" -eq 1 ]; then
  NODE_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)"
  log "demo URL: http://${NODE_IP:-<k3s-node-ip>}:8080"
else
  log "production URL: https://$DEFENSIVE_AI_PUBLIC_HOST"
fi
[ -z "$BACKUP_ID" ] || log "rollback point: bash install.sh --rollback $BACKUP_ID"
