#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="$APP_DIR"
CONFIG_DIR=""
DATA_DIR=""
PYTHON_BIN="${PYTHON_BIN:-python3}"
SERVICE_USER="${SERVICE_USER:-defensive-ai}"
SERVICE_GROUP="${SERVICE_GROUP:-defensive-ai}"
INSTALL_SYSTEMD=0
ENABLE_SERVICE=0
START_SERVICE=0
FORCE_CONFIG=0
DRY_RUN=0
DEMO_MODE=0

usage() {
  cat <<'EOF'
Usage:
  bash install.sh [options]

Options:
  --prefix DIR       Application directory. Defaults to the directory containing install.sh.
  --config-dir DIR   Directory for prod.yaml. Defaults to ./config, or /etc/defensive-ai-gateway with --systemd.
  --data-dir DIR     SQLite data directory. Defaults to ./data, or /var/lib/defensive-ai-gateway with --systemd.
  --python PATH      Python executable. Defaults to python3 or $PYTHON_BIN.
  --systemd          Install /etc/systemd/system/defensive-ai-gateway.service.
  --enable           Enable the systemd service. Implies --systemd.
  --start            Start/restart the systemd service. Implies --systemd.
  --force-config     Overwrite an existing prod.yaml.
  --demo-mode        Bind only loopback with one-person approval; never for production.
  --dry-run          Print actions without changing files.
  -h, --help         Show this help.

Examples:
  bash install.sh
  sudo bash install.sh --systemd --enable --start
  sudo DEFENSIVE_AI_API_TOKEN='<32+ chars>' DEFENSIVE_AI_APPROVER_TOKEN='<different 32+ chars>' bash install.sh --systemd
EOF
}

log() {
  printf '[install] %s\n' "$*"
}

die() {
  printf '[install] ERROR: %s\n' "$*" >&2
  exit 1
}

strong_secret() {
  value="$1"
  [ "${#value}" -ge 32 ] || return 1
  lower_value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$lower_value" in
    *replace*|*change-me*|*changeme*|*password*|*example*|*default*) return 1 ;;
  esac
  # These values are persisted in a systemd EnvironmentFile. Restrict them to
  # the portable token alphabet so parsing cannot change their value.
  case "$value" in *[!A-Za-z0-9._~+/=-]*) return 1 ;; esac
  return 0
}

load_protected_environment() {
  file="$1"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ""|\#*) continue ;; esac
    case "$line" in *=*) ;; *) die "invalid environment line in $file" ;; esac
    key="${line%%=*}"
    value="${line#*=}"
    case "$value" in *$'\r'*) die "environment values must be single-line" ;; esac
    case "$key" in
      DEFENSIVE_AI_API_TOKEN|DEFENSIVE_AI_INGEST_TOKEN|DEFENSIVE_AI_OPERATOR_TOKEN|DEFENSIVE_AI_APPROVER_TOKEN|\
      DEFENSIVE_AI_AUTH_LOOPBACK|DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN|DEFENSIVE_AI_DEMO_MODE|\
      DEFENSIVE_AI_HOST|DEFENSIVE_AI_APPROVAL_QUORUM|DEFENSIVE_AI_LLM_PROVIDER|\
      DEFENSIVE_AI_LLM_ENDPOINT|DEFENSIVE_AI_LLM_MODEL|DEFENSIVE_AI_LLM_ALLOWED_HOSTS|\
      DEFENSIVE_AI_LLM_API_KEY|DEFENSIVE_AI_DATA_RETENTION_DAYS|\
      DEFENSIVE_AI_AUDIT_RETENTION_DAYS|DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS)
        printf -v "$key" '%s' "$value"
        export "$key"
        ;;
      *) die "unsupported environment key in $file: $key" ;;
    esac
  done < "$file"
}

validate_production_tokens() {
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

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

wait_for_service_ready() {
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet defensive-ai-gateway.service \
      && "$PYTHON_ABS" -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/api/ready", timeout=2).read()' \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  systemctl status defensive-ai-gateway.service --no-pager >&2 || true
  journalctl -u defensive-ai-gateway.service -n 80 --no-pager >&2 || true
  return 1
}

need_root_for_systemd() {
  if [ "$INSTALL_SYSTEMD" -eq 1 ] && [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "--systemd requires root. Re-run with sudo, or run without --systemd for an unpacked local install."
  fi
}

abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$PWD/$1" ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix)
      [ "$#" -ge 2 ] || die "--prefix requires a value"
      PREFIX="$(abs_path "$2")"
      shift 2
      ;;
    --config-dir)
      [ "$#" -ge 2 ] || die "--config-dir requires a value"
      CONFIG_DIR="$(abs_path "$2")"
      shift 2
      ;;
    --data-dir)
      [ "$#" -ge 2 ] || die "--data-dir requires a value"
      DATA_DIR="$(abs_path "$2")"
      shift 2
      ;;
    --python)
      [ "$#" -ge 2 ] || die "--python requires a value"
      PYTHON_BIN="$2"
      shift 2
      ;;
    --systemd)
      INSTALL_SYSTEMD=1
      shift
      ;;
    --enable)
      INSTALL_SYSTEMD=1
      ENABLE_SERVICE=1
      shift
      ;;
    --start)
      INSTALL_SYSTEMD=1
      START_SERVICE=1
      shift
      ;;
    --force-config)
      FORCE_CONFIG=1
      shift
      ;;
    --demo-mode)
      DEMO_MODE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
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

need_root_for_systemd

if [ ! -d "$PREFIX/defensive_ai_gateway" ]; then
  die "application package not found under $PREFIX"
fi

if [ -z "$CONFIG_DIR" ]; then
  if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
    CONFIG_DIR="/etc/defensive-ai-gateway"
  else
    CONFIG_DIR="$PREFIX/config"
  fi
fi

if [ -z "$DATA_DIR" ]; then
  if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
    DATA_DIR="/var/lib/defensive-ai-gateway"
  else
    DATA_DIR="$PREFIX/data"
  fi
fi

CONFIG_FILE="$CONFIG_DIR/prod.yaml"
DB_PATH="$DATA_DIR/gateway.db"
ENV_FILE="$CONFIG_DIR/env"

# A caller-supplied value is an explicit rotation request and must win over the
# previous protected EnvironmentFile loaded for all other settings.
CALLER_API_TOKEN_SET="${DEFENSIVE_AI_API_TOKEN+x}"
CALLER_API_TOKEN="${DEFENSIVE_AI_API_TOKEN:-}"
CALLER_INGEST_TOKEN_SET="${DEFENSIVE_AI_INGEST_TOKEN+x}"
CALLER_INGEST_TOKEN="${DEFENSIVE_AI_INGEST_TOKEN:-}"
CALLER_OPERATOR_TOKEN_SET="${DEFENSIVE_AI_OPERATOR_TOKEN+x}"
CALLER_OPERATOR_TOKEN="${DEFENSIVE_AI_OPERATOR_TOKEN:-}"
CALLER_APPROVER_TOKEN_SET="${DEFENSIVE_AI_APPROVER_TOKEN+x}"
CALLER_APPROVER_TOKEN="${DEFENSIVE_AI_APPROVER_TOKEN:-}"

if [ "$INSTALL_SYSTEMD" -eq 1 ] && [ -f "$ENV_FILE" ]; then
  mode="$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null || true)"
  [ -n "$mode" ] || die "cannot read permissions for $ENV_FILE"
  [ "$((8#$mode & 077))" -eq 0 ] || die "$ENV_FILE must be chmod 600"
  # Parse only the generated KEY=value contract. Never execute a protected
  # EnvironmentFile as shell code during a privileged reinstall/rotation.
  load_protected_environment "$ENV_FILE"
  [ -z "$CALLER_API_TOKEN_SET" ] || export DEFENSIVE_AI_API_TOKEN="$CALLER_API_TOKEN"
  [ -z "$CALLER_INGEST_TOKEN_SET" ] || export DEFENSIVE_AI_INGEST_TOKEN="$CALLER_INGEST_TOKEN"
  [ -z "$CALLER_OPERATOR_TOKEN_SET" ] || export DEFENSIVE_AI_OPERATOR_TOKEN="$CALLER_OPERATOR_TOKEN"
  [ -z "$CALLER_APPROVER_TOKEN_SET" ] || export DEFENSIVE_AI_APPROVER_TOKEN="$CALLER_APPROVER_TOKEN"
fi

if [ "$DEMO_MODE" -eq 0 ]; then
  validate_production_tokens
  # The service never exposes bearer credentials over a node-wide plaintext
  # socket. Put a same-host TLS/mTLS reverse proxy in front of this loopback bind.
  SERVER_HOST="127.0.0.1"
  APPROVAL_QUORUM=2
  AUTH_LOOPBACK=false
  AUTH_REMOTE=true
  AUTH_DEMO=false
else
  SERVER_HOST="127.0.0.1"
  APPROVAL_QUORUM=1
  AUTH_LOOPBACK=true
  AUTH_REMOTE=false
  AUTH_DEMO=true
  log "WARNING: demo mode is loopback-only and not a production deployment"
fi

PYTHON_ABS="$(command -v "$PYTHON_BIN" || true)"
[ -n "$PYTHON_ABS" ] || die "Python executable not found: $PYTHON_BIN"

"$PYTHON_ABS" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required")
PY

log "application: $PREFIX"
log "config:      $CONFIG_FILE"
log "data:        $DATA_DIR"
log "python:      $PYTHON_ABS"

run mkdir -p "$CONFIG_DIR" "$DATA_DIR"

if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
      run useradd -r -s /usr/sbin/nologin -d "$DATA_DIR" "$SERVICE_USER"
    else
      log "useradd not found; create service user '$SERVICE_USER' manually if needed"
    fi
  fi
  if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    :
  elif command -v groupadd >/dev/null 2>&1; then
    run groupadd -r "$SERVICE_GROUP"
  fi
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    run chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
  fi
fi

if [ -f "$CONFIG_FILE" ] && [ "$FORCE_CONFIG" -ne 1 ]; then
  log "kept existing config: $CONFIG_FILE"
  if ! PYTHONPATH="$PREFIX${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON_ABS" - "$CONFIG_FILE" "$DEMO_MODE" <<'PY'
import ipaddress
import os
import sys

from defensive_ai_gateway.config import load_config

for name in (
    "DEFENSIVE_AI_HOST",
    "DEFENSIVE_AI_APPROVAL_QUORUM",
    "DEFENSIVE_AI_AUTH_LOOPBACK",
    "DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN",
    "DEFENSIVE_AI_DEMO_MODE",
):
    os.environ.pop(name, None)
config = load_config(sys.argv[1])
demo_mode = sys.argv[2] == "1"
try:
    loopback = ipaddress.ip_address(config.server.host).is_loopback
except ValueError:
    loopback = config.server.host.strip().lower() == "localhost"
if demo_mode:
    if not loopback or not config.auth.demo_mode or not config.auth.allow_loopback_no_token:
        raise SystemExit("existing config is not a loopback Demo config; rerun with --force-config")
else:
    if config.policy.approval_quorum < 2:
        raise SystemExit("existing config is not two-person approval; rerun with --force-config")
    if config.auth.allow_loopback_no_token or not config.auth.require_token_when_remote:
        raise SystemExit("existing config has a production auth bypass; rerun with --force-config")
    if config.auth.demo_mode:
        raise SystemExit("existing config still enables Demo mode; rerun with --force-config")
PY
  then
    die "existing config does not satisfy the selected mode"
  fi
else
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] write %s\n' "$CONFIG_FILE"
  else
    cat > "$CONFIG_FILE" <<EOF
server:
  host: "$SERVER_HOST"
  port: 8080
  max_connections: 256
  read_timeout_seconds: 15
  requests_per_minute: 12000
database:
  path: "$DB_PATH"
llm:
  provider: "local"
  endpoint: ""
  model: "local-rule-analyst"
  timeout_seconds: 30
  allowed_hosts: [127.0.0.1, localhost, "::1"]
  max_response_bytes: 2000000
  max_retries: 1
policy:
  mode: "read_only"
  max_prompt_chars: 12000
  max_context_bytes: 20000
  approval_quorum: $APPROVAL_QUORUM
  require_approval_for: [block, isolate, change_policy, disable_account]
  redact_fields: [password, token, cookie, authorization, customer_id, id_card, phone, email, session]
auth:
  api_token: ""
  ingest_token: ""
  operator_token: ""
  approver_token: ""
  allow_loopback_no_token: $AUTH_LOOPBACK
  require_token_when_remote: $AUTH_REMOTE
  demo_mode: $AUTH_DEMO
processing:
  async_enabled: true
  queue_max_size: 20000
  workers: 8
  max_attempts: 5
  retry_base_seconds: 1
operations:
  maintenance_interval_seconds: 60
  inbox_retention_days: 14
  stale_claim_seconds: 600
  data_retention_days: 90
  audit_retention_days: 365
  memory_history_retention_days: 365
syslog:
  embedded_listeners_enabled: false
  product_ports:
    waf: 15140
    hips: 15141
    ndr: 15142
    rasp: 15143
    siem: 15144
  gateway_profiles:
    waf: "auto-waf-json"
    hips: "auto-hips-json"
    ndr: "auto-ndr-json"
    rasp: "auto-rasp-json"
    siem: "auto-siem-json"
EOF
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    log "would write config: $CONFIG_FILE"
  else
    log "wrote config: $CONFIG_FILE"
  fi
fi

if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
  SERVICE_FILE="/etc/systemd/system/defensive-ai-gateway.service"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] write %s\n' "$SERVICE_FILE"
  else
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Defensive AI Gateway
After=network.target

[Service]
Type=simple
WorkingDirectory=$PREFIX
ExecStart=$PYTHON_ABS -m defensive_ai_gateway --config $CONFIG_FILE
Restart=always
RestartSec=3
User=$SERVICE_USER
Group=$SERVICE_GROUP
Environment=DEFENSIVE_AI_DB=$DB_PATH
Environment=PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=$ENV_FILE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
TasksMax=256
MemoryMax=2G
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
  fi
  log "wrote systemd service: $SERVICE_FILE"

  if [ "$DRY_RUN" -ne 1 ]; then
    umask 077
    ENV_TMP="$(mktemp "$CONFIG_DIR/.env.XXXXXX")"
    cat > "$ENV_TMP" <<EOF
DEFENSIVE_AI_API_TOKEN=${DEFENSIVE_AI_API_TOKEN:-}
DEFENSIVE_AI_INGEST_TOKEN=${DEFENSIVE_AI_INGEST_TOKEN:-}
DEFENSIVE_AI_OPERATOR_TOKEN=${DEFENSIVE_AI_OPERATOR_TOKEN:-}
DEFENSIVE_AI_APPROVER_TOKEN=${DEFENSIVE_AI_APPROVER_TOKEN:-}
DEFENSIVE_AI_AUTH_LOOPBACK=$([ "$DEMO_MODE" -eq 1 ] && printf 1 || printf 0)
DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN=$([ "$DEMO_MODE" -eq 1 ] && printf 0 || printf 1)
DEFENSIVE_AI_DEMO_MODE=$([ "$DEMO_MODE" -eq 1 ] && printf 1 || printf 0)
DEFENSIVE_AI_HOST=127.0.0.1
DEFENSIVE_AI_APPROVAL_QUORUM=$APPROVAL_QUORUM
DEFENSIVE_AI_LLM_PROVIDER=${DEFENSIVE_AI_LLM_PROVIDER:-local}
DEFENSIVE_AI_LLM_ENDPOINT=${DEFENSIVE_AI_LLM_ENDPOINT:-}
DEFENSIVE_AI_LLM_MODEL=${DEFENSIVE_AI_LLM_MODEL:-local-rule-analyst}
DEFENSIVE_AI_LLM_ALLOWED_HOSTS=${DEFENSIVE_AI_LLM_ALLOWED_HOSTS:-127.0.0.1,localhost,::1}
DEFENSIVE_AI_LLM_API_KEY=${DEFENSIVE_AI_LLM_API_KEY:-}
DEFENSIVE_AI_DATA_RETENTION_DAYS=${DEFENSIVE_AI_DATA_RETENTION_DAYS:-90}
DEFENSIVE_AI_AUDIT_RETENTION_DAYS=${DEFENSIVE_AI_AUDIT_RETENTION_DAYS:-365}
DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS=${DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS:-365}
EOF
    chmod 600 "$ENV_TMP"
    mv -f "$ENV_TMP" "$ENV_FILE"
  else
    printf '[dry-run] write protected environment %s\n' "$ENV_FILE"
  fi

  run systemctl daemon-reload
  if [ "$ENABLE_SERVICE" -eq 1 ]; then
    run systemctl enable defensive-ai-gateway.service
  fi
  if [ "$START_SERVICE" -eq 1 ]; then
    run systemctl restart defensive-ai-gateway.service
    if [ "$DRY_RUN" -ne 1 ]; then
      wait_for_service_ready || die "systemd service did not become ready"
    fi
  fi
fi

log "installation check passed"
log "start command: $PYTHON_ABS -m defensive_ai_gateway --config $CONFIG_FILE"
if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
  log "systemd status: systemctl status defensive-ai-gateway.service"
fi
