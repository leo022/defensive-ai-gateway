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
  --dry-run          Print actions without changing files.
  -h, --help         Show this help.

Examples:
  bash install.sh
  sudo bash install.sh --systemd --enable --start
  sudo DEFENSIVE_AI_API_TOKEN='change-me' bash install.sh --systemd
EOF
}

log() {
  printf '[install] %s\n' "$*"
}

die() {
  printf '[install] ERROR: %s\n' "$*" >&2
  exit 1
}

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
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
else
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] write %s\n' "$CONFIG_FILE"
  else
    cat > "$CONFIG_FILE" <<EOF
server:
  host: "0.0.0.0"
  port: 8080
database:
  path: "$DB_PATH"
llm:
  provider: "local"
  endpoint: ""
  model: "local-rule-analyst"
  timeout_seconds: 30
policy:
  mode: "read_only"
  max_prompt_chars: 12000
  max_context_bytes: 20000
  require_approval_for: [block, isolate, change_policy, disable_account]
  redact_fields: [password, token, cookie, authorization, customer_id, id_card, phone, email, session]
auth:
  api_token: ""
  allow_loopback_no_token: true
  require_token_when_remote: true
processing:
  async_enabled: true
  queue_max_size: 20000
  workers: 8
syslog:
  product_ports:
    waf: 15140
    hips: 15141
    ndr: 15142
    rasp: 15143
    siem: 15144
  gateway_profiles:
    rasp: "demo-rasp-json"
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
EnvironmentFile=-/etc/defensive-ai-gateway/env
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
  fi
  log "wrote systemd service: $SERVICE_FILE"

  if [ ! -f /etc/defensive-ai-gateway/env ] && [ "$DRY_RUN" -ne 1 ]; then
    cat > /etc/defensive-ai-gateway/env <<EOF
# Set this before exposing the service to non-loopback clients:
DEFENSIVE_AI_API_TOKEN=${DEFENSIVE_AI_API_TOKEN:-replace-with-a-strong-token}
DEFENSIVE_AI_LLM_API_KEY=${DEFENSIVE_AI_LLM_API_KEY:-replace-if-using-an-enterprise-llm-gateway}
EOF
    chmod 600 /etc/defensive-ai-gateway/env
  fi

  run systemctl daemon-reload
  if [ "$ENABLE_SERVICE" -eq 1 ]; then
    run systemctl enable defensive-ai-gateway.service
  fi
  if [ "$START_SERVICE" -eq 1 ]; then
    run systemctl restart defensive-ai-gateway.service
  fi
fi

log "installation check passed"
log "start command: $PYTHON_ABS -m defensive_ai_gateway --config $CONFIG_FILE"
if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
  log "systemd status: systemctl status defensive-ai-gateway.service"
fi
