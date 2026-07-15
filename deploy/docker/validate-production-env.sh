#!/usr/bin/env bash
set -euo pipefail

die() {
  printf '[docker-preflight] ERROR: %s\n' "$*" >&2
  exit 1
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

image="${DEFENSIVE_AI_IMAGE:-}"
case "$image" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *) die "DEFENSIVE_AI_IMAGE must use an immutable sha256 digest" ;;
esac

tokens=(
  "${DEFENSIVE_AI_API_TOKEN:-}"
  "${DEFENSIVE_AI_INGEST_TOKEN:-}"
  "${DEFENSIVE_AI_OPERATOR_TOKEN:-}"
  "${DEFENSIVE_AI_APPROVER_TOKEN:-}"
)
for token in "${tokens[@]}"; do
  strong_secret "$token" || die "every role token must be non-placeholder, at least 32 characters, and use the portable token alphabet"
done
for ((i = 0; i < ${#tokens[@]}; i++)); do
  for ((j = i + 1; j < ${#tokens[@]}; j++)); do
    [ "${tokens[$i]}" != "${tokens[$j]}" ] || die "role tokens must be distinct"
  done
done

provider="${DEFENSIVE_AI_LLM_PROVIDER:-local}"
endpoint="${DEFENSIVE_AI_LLM_ENDPOINT:-}"
model="${DEFENSIVE_AI_LLM_MODEL:-}"
allowed_hosts="${DEFENSIVE_AI_LLM_ALLOWED_HOSTS:-}"
single_line "$provider" && single_line "$endpoint" && single_line "$model" && single_line "$allowed_hosts" || die "LLM configuration values must be single-line"
[ -n "$model" ] || die "DEFENSIVE_AI_LLM_MODEL is required"
case "$provider" in
  local)
    [ -z "$endpoint" ] || die "local provider must not configure a remote endpoint"
    ;;
  ollama)
    case "$endpoint" in http://*|https://*) ;; *) die "Ollama endpoint must use http or https" ;; esac
    [ -n "$allowed_hosts" ] || die "Ollama requires DEFENSIVE_AI_LLM_ALLOWED_HOSTS"
    list_contains_host "$allowed_hosts" "$(endpoint_host "$endpoint")" || die "Ollama endpoint host must be explicitly allowlisted"
    ;;
  gateway)
    case "$endpoint" in https://*) ;; *) die "Gateway endpoint must use https" ;; esac
    [ -n "$allowed_hosts" ] || die "Gateway requires DEFENSIVE_AI_LLM_ALLOWED_HOSTS"
    list_contains_host "$allowed_hosts" "$(endpoint_host "$endpoint")" || die "Gateway endpoint host must be explicitly allowlisted"
    strong_secret "${DEFENSIVE_AI_LLM_API_KEY:-}" || die "Gateway API key must be at least 32 characters"
    ;;
  *) die "DEFENSIVE_AI_LLM_PROVIDER must be local, ollama, or gateway" ;;
esac

validate_retention DEFENSIVE_AI_DATA_RETENTION_DAYS "${DEFENSIVE_AI_DATA_RETENTION_DAYS:-90}"
validate_retention DEFENSIVE_AI_AUDIT_RETENTION_DAYS "${DEFENSIVE_AI_AUDIT_RETENTION_DAYS:-365}"
validate_retention DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS "${DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS:-365}"

printf '[docker-preflight] production environment is valid\n'
