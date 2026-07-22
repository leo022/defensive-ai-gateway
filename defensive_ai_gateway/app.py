from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import mimetypes
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .config import GatewayConfig, LLMConfig, load_config
from .database import Repository
from .json_safety import loads_bounded_json
from .log_adapter import (
    AUTO_PROFILE,
    LogAdapter,
    MappingProfile,
    SUPPORTED_PRODUCTS,
    builtin_product_profile,
    default_mapping_profile,
    demo_rasp_profile,
    explicit_product,
    fingerprint_product,
    mapping_profile_record,
    validate_raw_alert,
)
from .llm import (
    build_gateway_request,
    build_llm,
    is_anthropic_messages_endpoint,
    resolve_gateway_api_key,
)
from .memory import (
    LAYER_PRODUCT_LONG_TERM,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_PENDING,
    STATUS_QUARANTINED,
    STATUS_REVOKED,
    MemoryManager,
)
from .memory_matcher import MemoryMatcher
from .models import RawAlert, new_id, now_ms
from .normalizer import EventNormalizer
from .orchestrator import Orchestrator
from .policy import PolicyEngine
from .processing import AlertProcessor, AlertQueueFull, DeadLetter
from .skills import SkillRegistry
from .syslog_receiver import SyslogListenerSpec, SyslogReceiverManager
from .syslog_router import SyslogPortRouter


_STANDARD_ALERT_KEYS = ("event_type", "severity", "alert_id", "source", "timestamp")

# Hard cap on inbound request bodies to prevent memory-exhaustion DoS. A security
# alert payload is small JSON; anything larger is rejected before json.loads.
MAX_BODY_BYTES = 2_000_000

# Hosts permitted for the Ollama model-picker SSRF surface. The picker is meant
# to reach a local Ollama instance only; cloud-metadata / internal probes are
# refused. Production LLM endpoints go through the gateway adapter, not here.
_ALLOWED_OLLAMA_HOSTS = {"127.0.0.1", "localhost", "::1"}

_ROLE_READ = "read"
_ROLE_INGEST = "ingest"
_ROLE_ANALYST = "analyst"
_ROLE_APPROVER = "approver"
_ROLE_MEMORY = "memory"
_ROLE_CONFIG = "config"
_ALL_ROLES = {_ROLE_READ, _ROLE_INGEST, _ROLE_ANALYST, _ROLE_APPROVER, _ROLE_MEMORY, _ROLE_CONFIG}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not allowed", headers, fp)


def _open_model_endpoint(req: urllib.request.Request, timeout: float):
    """Open an allowlisted model endpoint without inheriting environment proxies."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    ).open(req, timeout=timeout)


def _open_ollama(req: urllib.request.Request, timeout: float):
    """Compatibility wrapper for the local Ollama picker/test paths."""
    return _open_model_endpoint(req, timeout)

_CASE_DISPOSITIONS = {
    "under_review": "escalate_case_review",
    "confirmed_attack": "confirm_case_attack",
    "closed": "close_case",
    "open": "reopen_case",
}

_CASE_DETAIL_SECTIONS = {"raw-alerts", "normalized-evidence", "analysis-runs"}


def _case_detail_summary(case_data: dict) -> dict:
    """Return the case metadata shared by the scoped detail endpoints."""
    fields = (
        "case_id",
        "product",
        "status",
        "severity",
        "classification",
        "confidence",
        "summary",
        "updated_at_ms",
    )
    return {field: case_data.get(field) for field in fields}


def _case_detail_section_payload(case_data: dict, section: str) -> dict:
    """Build a narrowly scoped case-detail response for the dedicated detail page."""
    linked_alerts = case_data.get("linked_alerts") or []
    if section == "raw-alerts":
        items = [
            {
                "record_type": "raw_alert",
                "alert_id": link.get("alert_id"),
                "event_id": link.get("event_id"),
                "linked_at_ms": link.get("linked_at_ms"),
                "disposition": link.get("disposition"),
                "data": link.get("raw_alert"),
            }
            for link in linked_alerts
            if link.get("raw_alert") is not None
        ]
    elif section == "normalized-evidence":
        items = [
            {
                "record_type": "normalized_evidence",
                "alert_id": link.get("alert_id"),
                "event_id": link.get("event_id"),
                "linked_at_ms": link.get("linked_at_ms"),
                "data": link.get("normalized_event"),
            }
            for link in linked_alerts
            if link.get("normalized_event") is not None
        ]
    elif section == "analysis-runs":
        items = [
            {"record_type": "agent_run", "data": run}
            for run in case_data.get("agent_runs") or []
        ]
        items.extend(
            {"record_type": "validation_run", "data": run}
            for run in case_data.get("validation_runs") or []
        )
    else:  # The HTTP handler validates the section before calling this helper.
        raise ValueError("unsupported case detail section")
    return {
        "case": _case_detail_summary(case_data),
        "section": section,
        "count": len(items),
        "items": items,
    }

_MEMORY_LAYERS = {
    "case_short_term", "product_long_term", "asset_profile", "org_knowledge", "evidence",
}
_MEMORY_STATUSES = {STATUS_ACTIVE, STATUS_PENDING, STATUS_EXPIRED, STATUS_QUARANTINED, STATUS_REVOKED}

_WEAK_TOKENS = {
    "changeme",
    "change-me",
    "replace-me",
    "replace-with-a-strong-token",
    "secret",
    "token",
}


class _PayloadTooLarge(Exception):
    """Raised when an inbound body exceeds ``MAX_BODY_BYTES``."""


class _UnsupportedMediaType(ValueError):
    """Raised when a JSON API receives a browser-simple non-JSON body."""


def _is_loopback_bind(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _loopback_authority(value: str) -> tuple[str, int | None] | None:
    """Parse an HTTP authority and accept only an actual loopback hostname/IP."""
    raw = str(value or "").strip()
    if not raw or any(character in raw for character in "\r\n\t"):
        return None
    try:
        parsed = urlparse(f"//{raw}")
        hostname = str(parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.username is not None
        or parsed.password is not None
        or not hostname
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return None
    if hostname == "localhost":
        return hostname, port
    try:
        if ipaddress.ip_address(hostname).is_loopback:
            return hostname, port
    except ValueError:
        pass
    return None


def _trusted_loopback_request_headers(host: str, origin: str = "") -> bool:
    """Reject DNS-rebinding authorities while preserving local CLI/Demo use."""
    host_authority = _loopback_authority(host)
    if host_authority is None:
        return False
    raw_origin = str(origin or "").strip()
    if not raw_origin:
        # Non-browser clients do not send Origin. Host still prevents a browser
        # origin using a rebound attacker-controlled hostname from receiving Demo
        # privileges.
        return True
    try:
        parsed_origin = urlparse(raw_origin)
        if (
            parsed_origin.scheme not in {"http", "https"}
            or not parsed_origin.netloc
            or parsed_origin.path not in {"", "/"}
            or parsed_origin.params
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            return False
        origin_authority = _loopback_authority(parsed_origin.netloc)
    except ValueError:
        return False
    if origin_authority is None or origin_authority[0] != host_authority[0]:
        return False
    origin_port = origin_authority[1] or (443 if parsed_origin.scheme == "https" else 80)
    host_port = host_authority[1]
    return host_port is None or host_port == origin_port


def _validate_exposed_server_config(config: GatewayConfig) -> None:
    """Fail closed for network-exposed deployments without strong identities.

    Localhost retains the zero-config Demo flow. Any non-loopback bind is a
    production boundary and must never silently start with a known placeholder,
    a loopback authentication bypass, or an impossible two-person quorum.
    """
    if _is_loopback_bind(config.server.host):
        return
    if config.syslog.embedded_listeners_enabled:
        raise ValueError(
            "network-exposed deployments must disable embedded Syslog listeners; "
            "use the authenticated external collector"
        )
    auth = config.auth
    if auth.demo_mode:
        return
    if auth.allow_loopback_no_token or not auth.require_token_when_remote:
        raise ValueError(
            "network-exposed deployments must disable loopback auth bypass "
            "and require remote tokens"
        )
    tokens = {
        "api": str(auth.api_token or "").strip(),
        "ingest": str(auth.ingest_token or "").strip(),
        "operator": str(auth.operator_token or "").strip(),
        "approver": str(auth.approver_token or "").strip(),
    }
    fixed_actors = {"api-admin", "ingest-collector", "soc-operator", "soc-approver"}
    named_actors: set[str] = set()
    named_approvers: set[str] = set()
    for principal in auth.principals:
        actor = str(principal.actor or "").strip()
        roles = {str(role).strip().lower() for role in principal.roles}
        if not actor:
            raise ValueError("named auth principals require a non-empty actor")
        if actor in fixed_actors or actor in named_actors:
            raise ValueError(f"duplicate auth principal actor: {actor}")
        if not roles or not roles.issubset(_ALL_ROLES):
            raise ValueError(f"named auth principal '{actor}' has invalid roles")
        token = str(principal.token or "").strip()
        if not token:
            raise ValueError(f"named auth principal '{actor}' has no token")
        tokens[f"principal:{actor}"] = token
        named_actors.add(actor)
        if _ROLE_APPROVER in roles:
            named_approvers.add(actor)
    if not tokens["api"]:
        raise ValueError("network-exposed deployments require DEFENSIVE_AI_API_TOKEN")
    for name, token in tokens.items():
        if token and (len(token) < 24 or token.lower() in _WEAK_TOKENS):
            raise ValueError(f"{name} token must be at least 24 characters and not a placeholder")
    configured = [token for token in tokens.values() if token]
    if len(configured) != len(set(configured)):
        raise ValueError("configured role tokens must be distinct")
    approval_actors = {"api-admin"}
    if tokens["approver"]:
        approval_actors.add("soc-approver")
    approval_actors.update(named_approvers)
    if len(approval_actors) < config.policy.approval_quorum:
        raise ValueError(
            "approval quorum requires enough distinct authenticated approver principals"
        )


def _looks_like_standard_alert(payload: dict) -> bool:
    """Heuristic: payload carries standard alert top-level fields but omitted product."""
    return any(k in payload for k in _STANDARD_ALERT_KEYS)


def _build_raw_alert(payload: dict, product: str) -> RawAlert:
    alert = RawAlert(
        source=str(payload.get("source", "direct")),
        product=product,
        event_type=str(payload.get("event_type", "unknown")),
        severity=str(payload.get("severity", "medium")),
        timestamp=str(payload.get("timestamp", "")),
        payload=dict(payload.get("payload", payload)),
        alert_id=str(payload.get("alert_id") or payload.get("id") or ""),
    )
    if not alert.alert_id:
        alert.alert_id = new_id("alert")
    return alert


def _validate_raw_alert(alert: RawAlert) -> RawAlert:
    """Backward-compatible alias for the shared adapter/production contract."""
    return validate_raw_alert(alert)


def _ollama_tags_url(endpoint: str) -> str:
    """Derive the Ollama ``/api/tags`` URL from a configured generate endpoint."""
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return "http://127.0.0.1:11434/api/tags"
    if endpoint.endswith("/api/generate"):
        return endpoint[: -len("/api/generate")] + "/api/tags"
    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/api/tags"
    return "http://127.0.0.1:11434/api/tags"


def _validated_llm_endpoint(provider: str, endpoint: str, allowed_hosts: list[str]) -> str:
    """Validate the model destination before any prompt or credential can leave."""
    provider = provider.strip().lower()
    endpoint = endpoint.strip()
    if provider == "local":
        return ""
    if provider not in {"ollama", "gateway"}:
        raise ValueError(f"unsupported LLM provider: {provider}")
    if not endpoint:
        if provider == "ollama":
            endpoint = "http://127.0.0.1:11434/api/generate"
        else:
            raise ValueError("gateway endpoint is required")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("LLM endpoint must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("LLM endpoint must not contain embedded credentials")
    host = parsed.hostname.lower()
    allowed = {str(item).strip().lower() for item in allowed_hosts if str(item).strip()}
    if provider == "ollama":
        if host not in _ALLOWED_OLLAMA_HOSTS and host not in allowed:
            raise ValueError(
                "Ollama endpoint is not in the configured allowlist (llm.allowed_hosts); explicitly allow the service host"
            )
        try:
            resolved = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 11434, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise ValueError(f"cannot resolve Ollama endpoint: {exc}") from exc
        addresses = [ipaddress.ip_address(address) for address in resolved]
        if not addresses:
            raise ValueError("Ollama endpoint did not resolve")
        if host in _ALLOWED_OLLAMA_HOSTS:
            if any(not address.is_loopback for address in addresses):
                raise ValueError("local Ollama endpoint resolved outside loopback")
        elif any(
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            for address in addresses
        ):
            raise ValueError("Ollama endpoint resolved to a prohibited address range")
        return endpoint
    if host not in allowed:
        raise ValueError(f"gateway host '{host}' is not in llm.allowed_hosts")
    if parsed.scheme != "https" and host not in _ALLOWED_OLLAMA_HOSTS:
        raise ValueError("non-loopback Gateway endpoints must use HTTPS")
    try:
        resolved = {
            item[4][0]
            for item in socket.getaddrinfo(
                host,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        }
    except OSError as exc:
        raise ValueError(f"cannot resolve Gateway endpoint: {exc}") from exc
    addresses = [ipaddress.ip_address(address) for address in resolved]
    if not addresses:
        raise ValueError("Gateway endpoint did not resolve")
    if host in _ALLOWED_OLLAMA_HOSTS:
        if any(not address.is_loopback for address in addresses):
            raise ValueError("local Gateway endpoint resolved outside loopback")
    elif any(
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        for address in addresses
    ):
        raise ValueError("Gateway endpoint resolved to a prohibited address range")
    return endpoint


def _query_first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    return str(query.get(key, [default])[0] or "").strip()


def _query_int(query: dict[str, list[str]], key: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        value = int(_query_first(query, key, str(default)))
    except (TypeError, ValueError):
        value = default
    if min_value is not None:
        value = max(value, min_value)
    if max_value is not None:
        value = min(value, max_value)
    return value


def _query_optional_int(query: dict[str, list[str]], key: str) -> int | None:
    raw = _query_first(query, key)
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


class GatewayState:
    def __init__(self, config: GatewayConfig, config_path: str = ""):
        self.config = config
        self.config_path = config_path
        self.lock = threading.RLock()
        self.repo = Repository(config.database.path)
        self._restore_runtime_settings()
        self.policy = PolicyEngine(config.policy)
        self.normalizer = EventNormalizer(self.policy)
        self.memory = MemoryManager(self.repo, self.policy)
        self.skills = SkillRegistry()
        self.llm = build_llm(config.llm)
        self.log_adapter = LogAdapter(self.normalizer)
        self._seed_mapping_profiles()
        self.orchestrator = Orchestrator(
            self.repo,
            self.normalizer,
            self.memory,
            self.llm,
            self.policy,
            skills=self.skills,
            memory_matcher=MemoryMatcher(config.memory_matching),
        )
        self.syslog_receiver = SyslogReceiverManager(
            config.server.host,
            self._handle_syslog_message,
            max_frame_bytes=config.syslog.max_frame_bytes,
            max_connections=config.syslog.max_connections,
        )
        self._dispatcher_stop = threading.Event()
        self._dispatcher_wakeup = threading.Event()
        self._dispatcher_thread: threading.Thread | None = None
        self._maintenance_stop = threading.Event()
        self._maintenance_thread: threading.Thread | None = None
        self._maintenance_last_success_ms = now_ms()
        self._maintenance_last_error = ""
        self._maintenance_consecutive_failures = 0
        self.repo.recover_stale_inbox(now_ms())
        self.alert_processor = (
            AlertProcessor(
                self._handle_queued_alert,
                max_size=config.processing.queue_max_size,
                workers=config.processing.workers,
                # Durable inbox attempts are authoritative. Each claim receives
                # one in-memory execution attempt before durable retry/DLQ.
                max_attempts=1,
                dead_letter_handler=self._persist_dead_letter,
            )
            if config.processing.async_enabled
            else None
        )
        if self.alert_processor:
            self.alert_processor.start()
            self._dispatcher_thread = threading.Thread(
                target=self._dispatch_inbox,
                name="durable-alert-dispatcher",
                daemon=True,
            )
            self._dispatcher_thread.start()
        if config.syslog.embedded_listeners_enabled:
            self._activate_configured_syslog_listeners()
        self._maintenance_thread = threading.Thread(
            target=self._maintenance_loop,
            name="governance-maintenance",
            daemon=True,
        )
        self._maintenance_thread.start()

    def _restore_runtime_settings(self) -> None:
        saved_llm = self.repo.get_runtime_setting("llm")
        if isinstance(saved_llm, dict):
            try:
                current = self.config.llm
                provider = str(saved_llm.get("provider", current.provider)).lower()
                endpoint = _validated_llm_endpoint(
                    provider,
                    str(saved_llm.get("endpoint", current.endpoint)),
                    current.allowed_hosts,
                )
                same_destination = provider == current.provider and endpoint == current.endpoint
                self.config.llm = LLMConfig(
                    provider=provider,
                    endpoint=endpoint,
                    api_key_env=current.api_key_env,
                    api_key=current.api_key if same_destination else "",
                    model=str(saved_llm.get("model", current.model)),
                    timeout_seconds=max(
                        1,
                        min(int(saved_llm.get("timeout_seconds", current.timeout_seconds)), 300),
                    ),
                    allowed_hosts=list(current.allowed_hosts),
                    max_response_bytes=current.max_response_bytes,
                    max_retries=current.max_retries,
                )
            except (TypeError, ValueError, RuntimeError) as exc:
                self.repo.insert_audit(
                    new_id("audit"),
                    "runtime-config",
                    "system",
                    "runtime_llm_restore_rejected",
                    {"error": str(exc)},
                )
        saved_syslog = self.repo.get_runtime_setting("syslog")
        if isinstance(saved_syslog, dict) and self.config.syslog.embedded_listeners_enabled:
            ports = saved_syslog.get("product_ports")
            protocols = saved_syslog.get("product_protocols")
            if isinstance(ports, dict):
                self.config.syslog.product_ports.update(
                    {
                        str(product): int(port)
                        for product, port in ports.items()
                        if str(product) in SUPPORTED_PRODUCTS and 1 <= int(port) <= 65535
                    }
                )
            if isinstance(protocols, dict):
                self.config.syslog.product_protocols.update(
                    {
                        str(product): str(protocol).lower()
                        for product, protocol in protocols.items()
                        if str(product) in SUPPORTED_PRODUCTS
                        and str(protocol).lower() in {"tcp", "udp"}
                    }
                )

    def _handle_queued_alert(self, alert: RawAlert):
        result = self.orchestrator.handle_alert(alert)
        if not self.repo.complete_inbox_alert(alert.alert_id):
            raise RuntimeError(f"durable inbox completion failed for {alert.alert_id}")
        return result

    @staticmethod
    def _raw_alert_from_inbox(record: dict) -> RawAlert:
        payload = record.get("raw_alert") or {}
        return RawAlert(
            source=str(payload.get("source") or "unknown"),
            product=str(payload.get("product") or "siem"),
            event_type=str(payload.get("event_type") or "unknown"),
            severity=str(payload.get("severity") or "medium"),
            timestamp=str(payload.get("timestamp") or ""),
            payload=dict(payload.get("payload") or {}),
            alert_id=str(payload.get("alert_id") or record.get("alert_id") or ""),
            trusted_sample=bool(payload.get("trusted_sample", False)),
        )

    def _dispatch_inbox(self) -> None:
        while not self._dispatcher_stop.is_set():
            stats = self.alert_processor.stats() if self.alert_processor else None
            if stats and stats.queued >= stats.queue_max_size:
                self._dispatcher_wakeup.wait(0.1)
                self._dispatcher_wakeup.clear()
                continue
            claimed = self.repo.claim_inbox_alert()
            if not claimed:
                self._dispatcher_wakeup.wait(0.2)
                self._dispatcher_wakeup.clear()
                continue
            alert = self._raw_alert_from_inbox(claimed)
            try:
                self.alert_processor.submit(alert)
            except AlertQueueFull:
                self.repo.fail_inbox_alert(
                    alert.alert_id,
                    "execution_queue_full",
                    retry_delay_ms=250,
                )
                self._dispatcher_wakeup.wait(0.1)
                self._dispatcher_wakeup.clear()

    def _persist_dead_letter(self, entry: DeadLetter) -> None:
        delay_ms = int(self.config.processing.retry_base_seconds * 1000)
        status = self.repo.fail_inbox_alert(
            entry.alert.alert_id,
            entry.error or entry.reason,
            retry_delay_ms=delay_ms,
        )
        if status == "dead_letter":
            self.repo.insert_audit(
                new_id("audit"),
                entry.alert.alert_id,
                "durable-alert-processor",
                "alert_dead_lettered",
                entry.to_dict(),
            )

    def _activate_configured_syslog_listeners(self) -> None:
        specs = [
            SyslogListenerSpec(
                product,
                int(port),
                str(self.config.syslog.product_protocols.get(product, "tcp")).lower(),
            )
            for product, port in self.config.syslog.product_ports.items()
            if product in SUPPORTED_PRODUCTS
        ]
        try:
            self.syslog_receiver.update(specs)
        except OSError as exc:
            print(f"[syslog] configured embedded listeners could not all start: {exc}")

    def _maintenance_loop(self) -> None:
        interval = self.config.operations.maintenance_interval_seconds
        while not self._maintenance_stop.wait(interval):
            try:
                current_ms = now_ms()
                # Serialize automatic lifecycle transitions with analyst actions.
                # MemoryManager also owns a lifecycle lock for orchestrator calls,
                # while this state lock keeps the API's multi-step view coherent.
                with self.lock:
                    expired = self.memory.expire_due()
                    conflicts = []
                    for product in sorted(SUPPORTED_PRODUCTS):
                        conflicts.extend(self.memory.detect_conflicts(product))
                recovered = self.repo.recover_stale_inbox(
                    current_ms - self.config.operations.stale_claim_seconds * 1000
                )
                purged = self.repo.purge_completed_inbox(
                    current_ms
                    - self.config.operations.inbox_retention_days * 24 * 3600 * 1000
                )
                operations = self.config.operations
                retention = self.repo.purge_retained_history(
                    data_before_ms=(
                        current_ms - operations.data_retention_days * 24 * 3600 * 1000
                        if operations.data_retention_days
                        else None
                    ),
                    audit_before_ms=(
                        current_ms - operations.audit_retention_days * 24 * 3600 * 1000
                        if operations.audit_retention_days
                        else None
                    ),
                    memory_before_ms=(
                        current_ms - operations.memory_history_retention_days * 24 * 3600 * 1000
                        if operations.memory_history_retention_days
                        else None
                    ),
                    limit=operations.retention_batch_size,
                )
                if expired or conflicts or recovered or purged or any(retention.values()):
                    self.repo.insert_audit(
                        new_id("audit"),
                        "maintenance",
                        "governance-maintenance",
                        "maintenance_completed",
                        {
                            "expired_memories": len(expired),
                            "memory_conflicts": len(conflicts),
                            "recovered_inbox": recovered,
                            "purged_inbox": purged,
                            "retention": retention,
                        },
                    )
                if recovered:
                    self._dispatcher_wakeup.set()
                with self.lock:
                    self._maintenance_last_success_ms = now_ms()
                    self._maintenance_last_error = ""
                    self._maintenance_consecutive_failures = 0
            except Exception as exc:  # noqa: BLE001
                with self.lock:
                    self._maintenance_consecutive_failures += 1
                    failures = self._maintenance_consecutive_failures
                    self._maintenance_last_error = type(exc).__name__
                print(f"[gateway] maintenance failed: {exc!r}")
                try:
                    self.repo.insert_audit(
                        new_id("audit"),
                        "maintenance",
                        "governance-maintenance",
                        "maintenance_failed",
                        {
                            "error_type": type(exc).__name__,
                            "consecutive_failures": failures,
                        },
                    )
                except Exception as audit_exc:  # noqa: BLE001
                    print(f"[gateway] maintenance failure audit failed: {audit_exc!r}")

    def stop_alert_processor(self) -> None:
        self._dispatcher_stop.set()
        self._dispatcher_wakeup.set()
        if self._dispatcher_thread:
            self._dispatcher_thread.join(timeout=2)
        if self.alert_processor:
            self.alert_processor.stop()

    def stop(self) -> None:
        self.syslog_receiver.stop()
        self._maintenance_stop.set()
        if self._maintenance_thread:
            self._maintenance_thread.join(timeout=2)
        self.stop_alert_processor()

    def _handle_syslog_message(self, spec: SyslogListenerSpec, data: bytes, peer: str) -> None:
        with self.lock:
            router = SyslogPortRouter(self.config.syslog.product_ports, self.config.syslog.gateway_profiles)
            routed = router.route(
                spec.port,
                data,
                hostname=peer,
                appname=spec.product,
                protocol=spec.protocol,
            )
            alert = self.alert_from_payload(routed.payload, routed.profile_id)
        self.submit_alert(alert)

    def processing_stats(self) -> dict:
        inbox = self.repo.inbox_stats()
        durable_waiting = int(inbox.get("pending", 0)) + int(inbox.get("retry", 0))
        durable_processing = int(inbox.get("processing", 0))
        unfinished = durable_waiting + durable_processing
        if not self.alert_processor:
            accepted = sum(int(value) for value in inbox.values())
            return {
                "enabled": False,
                "queue_max_size": 0,
                "workers": 0,
                "queued": durable_waiting,
                "inflight": durable_processing,
                "unfinished": unfinished,
                "submitted": accepted,
                "processed": int(inbox.get("completed", 0)),
                "failed": 0,
                "retried": inbox.get("retry", 0),
                "dead_lettered": inbox.get("dead_letter", 0),
                "rejected": 0,
                "durable_inbox": inbox,
            }
        stats = self.alert_processor.stats().to_dict()
        executor_queued = int(stats.get("queued", 0))
        executor_inflight = int(stats.get("inflight", 0))
        # The dispatcher marks durable rows as processing before submitting them
        # to the execution queue. Separate actual workers from claimed-but-waiting
        # alerts so the dashboard does not report an empty queue while work is
        # still waiting behind a busy worker pool.
        analyzing = min(durable_processing, executor_inflight)
        stats["submitted"] = sum(int(value) for value in inbox.values())
        stats["processed"] = int(inbox.get("completed", 0))
        stats["queued"] = max(0, unfinished - analyzing)
        stats["inflight"] = analyzing
        stats["unfinished"] = unfinished
        stats["executor_queued"] = executor_queued
        stats["executor_inflight"] = executor_inflight
        stats["failed"] = int(inbox.get("dead_letter", 0))
        stats["dead_lettered"] = int(inbox.get("dead_letter", 0))
        stats["durable_inbox"] = inbox
        return stats

    def readiness(self) -> dict:
        """Return dependency health used by readiness and operator diagnostics."""
        database = self.repo.readiness_check()
        inbox = self.repo.inbox_stats()
        backlog = sum(int(inbox.get(status, 0)) for status in ("pending", "retry", "processing"))
        capacity_ok = (
            not self.alert_processor
            or backlog < self.config.processing.queue_max_size
        )
        processor_ok = (
            True if not self.alert_processor else self.alert_processor.is_healthy()
        )
        dispatcher_ok = (
            True
            if not self.alert_processor
            else bool(self._dispatcher_thread and self._dispatcher_thread.is_alive())
        )
        maintenance_age_ms = max(0, now_ms() - self._maintenance_last_success_ms)
        maintenance_deadline_ms = max(
            60_000,
            self.config.operations.maintenance_interval_seconds * 3 * 1000,
        )
        maintenance_ok = bool(
            self._maintenance_thread
            and self._maintenance_thread.is_alive()
            and self._maintenance_consecutive_failures < 3
            and maintenance_age_ms <= maintenance_deadline_ms
        )
        listeners = self.syslog_receiver.status()
        expected_listener_count = (
            len(self.config.syslog.product_ports)
            if self.config.syslog.embedded_listeners_enabled
            else 0
        )
        syslog_ok = (
            not self.config.syslog.embedded_listeners_enabled
            or (
                len(listeners) == expected_listener_count
                and all(bool(listener.get("active")) for listener in listeners)
            )
        )
        checks = {
            "database": database,
            "processor": {"ok": processor_ok},
            "dispatcher": {"ok": dispatcher_ok},
            "maintenance": {
                "ok": maintenance_ok,
                "last_success_age_ms": maintenance_age_ms,
                "consecutive_failures": self._maintenance_consecutive_failures,
                "last_error": self._maintenance_last_error,
            },
            "inbox_capacity": {
                "ok": capacity_ok,
                "backlog": backlog,
                "capacity": self.config.processing.queue_max_size,
            },
            "syslog": {
                "ok": syslog_ok,
                "expected": expected_listener_count,
                "active": sum(1 for listener in listeners if listener.get("active")),
            },
        }
        return {
            "ok": all(bool(check.get("ok")) for check in checks.values()),
            "checks": checks,
        }

    def submit_alert(self, alert: RawAlert) -> dict:
        alert = _validate_raw_alert(alert)
        if self.alert_processor:
            enqueue_status = self.repo.enqueue_alert_bounded(
                alert,
                max_attempts=self.config.processing.max_attempts,
                capacity=self.config.processing.queue_max_size,
            )
            if enqueue_status == "duplicate":
                existing = self.repo.get_inbox_alert(alert.alert_id) or {}
                return {
                    "ok": True,
                    "status": existing.get("status", "duplicate"),
                    "alert_id": alert.alert_id,
                    "product": alert.product,
                    "duplicate": True,
                    "durable": True,
                    "queue": self.processing_stats(),
                }
            if enqueue_status == "full":
                raise AlertQueueFull("durable alert inbox is full")
            self._dispatcher_wakeup.set()
            return {
                "ok": True,
                "status": "queued",
                "durable": True,
                "alert_id": alert.alert_id,
                "product": alert.product,
                "recovered": enqueue_status == "recovered",
                "queue": self.processing_stats(),
            }
        self.repo.enqueue_alert(alert, max_attempts=self.config.processing.max_attempts)
        claimed = self.repo.claim_inbox_alert(alert.alert_id)
        if not claimed:
            existing = self.repo.get_agent_result_for_event(
                self.normalizer.normalize(alert).event_id
            )
            return existing or {"ok": True, "status": "duplicate", "alert_id": alert.alert_id}
        try:
            result = self.orchestrator.handle_alert(self._raw_alert_from_inbox(claimed))
            self.repo.complete_inbox_alert(alert.alert_id)
            return result.to_dict()
        except Exception as exc:
            self.repo.fail_inbox_alert(
                alert.alert_id,
                repr(exc),
                retry_delay_ms=int(self.config.processing.retry_base_seconds * 1000),
            )
            raise

    def _seed_mapping_profiles(self) -> None:
        self.repo.delete_mapping_profile("demo-waf-json")
        for profile in [default_mapping_profile(), demo_rasp_profile()]:
            if not self.repo.get_mapping_profile(profile.profile_id):
                self.repo.save_mapping_profile(mapping_profile_record(profile))
        for product in sorted(SUPPORTED_PRODUCTS):
            profile_id = AUTO_PROFILE.get(product, f"auto-{product}-json")
            if self.repo.get_mapping_profile(profile_id):
                continue
            try:
                profile = builtin_product_profile(product)
                profile.profile_id = profile_id
                self.repo.save_mapping_profile(mapping_profile_record(profile))
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self.repo.insert_audit(
                    new_id("audit"),
                    "mapping-profile-seed",
                    "gateway",
                    "mapping_profile_seed_skipped",
                    {"product": product, "profile_id": profile_id, "error": str(exc)},
                )

    def llm_config_payload(self) -> dict:
        with self.lock:
            llm = self.config.llm
            return {
                "provider": llm.provider,
                "endpoint": llm.endpoint,
                "api_key_env": llm.api_key_env,
                "api_key_set": bool(
                    resolve_gateway_api_key(llm.endpoint, llm.api_key, llm.api_key_env)
                    if llm.provider == "gateway"
                    else llm.api_key
                ),
                "model": llm.model,
                "timeout_seconds": llm.timeout_seconds,
            }

    def update_llm_config(self, payload: dict) -> dict:
        with self.lock:
            current = self.config.llm
            provider = str(payload.get("provider", current.provider)).strip().lower() or current.provider
            endpoint = _validated_llm_endpoint(
                provider,
                str(payload.get("endpoint", current.endpoint)),
                current.allowed_hosts,
            )
            api_key = str(payload.get("api_key", "")).strip()
            same_destination = provider == current.provider and endpoint == current.endpoint
            if not api_key and payload.get("keep_existing_key", True) and same_destination:
                api_key = current.api_key
            updated = LLMConfig(
                provider=provider,
                endpoint=endpoint,
                # Environment variable names are deployment policy, never client input.
                api_key_env=current.api_key_env,
                api_key=api_key,
                model="local-rule-analyst" if provider == "local" else str(payload.get("model", current.model)).strip() or current.model,
                timeout_seconds=max(1, min(int(payload.get("timeout_seconds", current.timeout_seconds)), 300)),
                allowed_hosts=list(current.allowed_hosts),
                max_response_bytes=current.max_response_bytes,
                max_retries=current.max_retries,
            )
            self.config.llm = updated
            self.llm = build_llm(updated)
            self.orchestrator = Orchestrator(
                self.repo,
                self.normalizer,
                self.memory,
                self.llm,
                self.policy,
                skills=self.skills,
                memory_matcher=MemoryMatcher(self.config.memory_matching),
            )
            self.repo.insert_audit(
                new_id("audit"),
                "runtime-config",
                str(payload.get("_actor") or "runtime-operator"),
                "llm_config_updated",
                {
                    "provider": updated.provider,
                    "model": updated.model,
                    "endpoint_host": urlparse(updated.endpoint).hostname or "",
                    "api_key_set": bool(updated.api_key),
                    "timeout_seconds": updated.timeout_seconds,
                },
            )
            self.repo.set_runtime_setting(
                "llm",
                {
                    "provider": updated.provider,
                    "endpoint": updated.endpoint,
                    "model": updated.model,
                    "timeout_seconds": updated.timeout_seconds,
                },
                updated_by=str(payload.get("_actor") or "runtime-operator"),
            )
            return self.llm_config_payload()

    def list_ollama_models(self, endpoint_override: str = "") -> dict:
        """List models available in the local Ollama instance.

        Derives the Ollama ``/api/tags`` URL from ``endpoint_override`` (the
        value currently typed in the dashboard form) when provided, otherwise
        from the configured LLM endpoint. Decoupling from the saved provider
        lets the picker work as soon as the operator selects ``ollama`` and
        enters an endpoint, before the configuration is saved.
        """
        with self.lock:
            llm = self.config.llm
            provider = llm.provider
            endpoint = (endpoint_override or llm.endpoint).strip()
        try:
            endpoint = _validated_llm_endpoint("ollama", endpoint, llm.allowed_hosts)
        except ValueError as exc:
            return {
                "ok": False,
                "provider": provider,
                "endpoint": endpoint,
                "models": [],
                "error": str(exc),
            }
        tags_url = _ollama_tags_url(endpoint)
        try:
            # Validate the derived URL too, immediately before opening it. This
            # keeps list/test behavior aligned with the analysis client while
            # retaining the DNS/range SSRF checks for explicit remote services.
            tags_url = _validated_llm_endpoint("ollama", tags_url, llm.allowed_hosts)
            req = urllib.request.Request(tags_url, headers={"Accept": "application/json"}, method="GET")
            with _open_ollama(req, timeout=10) as resp:
                raw = resp.read(self.config.llm.max_response_bytes + 1)
                if len(raw) > self.config.llm.max_response_bytes:
                    raise ValueError("Ollama model list response is too large")
                data = loads_bounded_json(raw.decode("utf-8"))
            models: list[str] = []
            for item in data.get("models", []) or []:
                name = item.get("name") or item.get("model")
                if name:
                    models.append(str(name))
            return {
                "ok": True,
                "provider": provider,
                "endpoint": tags_url,
                "models": sorted(models),
                "error": "",
            }
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator via UI
            return {
                "ok": False,
                "provider": provider,
                "endpoint": tags_url,
                "models": [],
                "error": str(exc),
            }

    def test_llm_connection(self, payload: dict) -> dict:
        """Test LLM connectivity using the supplied form values (before saving).

        Accepts the form fields directly so the operator can verify reachability
        and credentials without persisting the configuration first. This mirrors
        the ``list_ollama_models`` pattern but generalizes across all three
        providers: local (always ok), ollama (hit /api/tags), and gateway (light
        POST with auth).
        """
        provider = str(payload.get("provider", "")).strip().lower()
        endpoint = str(payload.get("endpoint", "")).strip()
        api_key = str(payload.get("api_key", "")).strip()
        model = str(payload.get("model", "")).strip()
        timeout = max(1, min(int(payload.get("timeout_seconds", 15)), 30))

        if provider == "local":
            return {
                "ok": True,
                "provider": "local",
                "message": "本地分析器在进程内运行，无需网络连接。",
                "detail": "",
            }

        if provider not in {"ollama", "gateway"}:
            raise ValueError(f"unsupported LLM provider: {provider or '<empty>'}")

        if provider == "ollama":
            endpoint = _validated_llm_endpoint("ollama", endpoint, self.config.llm.allowed_hosts)
            tags_url = _ollama_tags_url(endpoint)
            try:
                tags_url = _validated_llm_endpoint(
                    "ollama", tags_url, self.config.llm.allowed_hosts
                )
                req = urllib.request.Request(tags_url, headers={"Accept": "application/json"}, method="GET")
                with _open_ollama(req, timeout=min(timeout, 10)) as resp:
                    raw = resp.read(self.config.llm.max_response_bytes + 1)
                    if len(raw) > self.config.llm.max_response_bytes:
                        raise ValueError("Ollama response is too large")
                    data = loads_bounded_json(raw.decode("utf-8"))
                models = [str(m.get("name") or m.get("model", "")) for m in data.get("models", [])]
                return {
                    "ok": True,
                    "provider": "ollama",
                    "endpoint": tags_url,
                    "message": f"Ollama 可达，已加载 {len(models)} 个模型。",
                    "detail": f"{len(models)} 个模型",
                }
            except urllib.error.HTTPError as exc:
                return {
                    "ok": False,
                    "provider": "ollama",
                    "endpoint": tags_url,
                    "message": f"Ollama 返回 HTTP {exc.code}，请确认服务已启动。",
                    "detail": exc.read().decode("utf-8", errors="ignore")[:200],
                }
            except urllib.error.URLError as exc:
                return {
                    "ok": False,
                    "provider": "ollama",
                    "endpoint": tags_url,
                    "message": f"Ollama 不可达：{exc.reason}",
                    "detail": str(exc.reason),
                }
            except Exception as exc:
                return {
                    "ok": False,
                    "provider": "ollama",
                    "endpoint": tags_url,
                    "message": f"Ollama 探测失败：{exc}",
                    "detail": str(exc),
                }

        # gateway (and any future provider) — send a lightweight authenticated POST
        # and verify the endpoint returns valid JSON.
        endpoint = _validated_llm_endpoint("gateway", endpoint, self.config.llm.allowed_hosts)

        # A saved credential may only be reused for its exact saved destination.
        # The caller can provide a one-off key, but can never select an env name.
        with self.lock:
            saved_key = self.config.llm.api_key
            same_destination = provider == self.config.llm.provider and endpoint == self.config.llm.endpoint
            api_key_env = self.config.llm.api_key_env if same_destination else ""
        resolved_key = resolve_gateway_api_key(
            endpoint,
            api_key or (saved_key if same_destination else ""),
            api_key_env,
        )

        try:
            req = build_gateway_request(
                endpoint,
                model or "probe",
                "Reply with exactly: OK",
                {},
                resolved_key,
                max_tokens=32,
            )
            with _open_model_endpoint(req, timeout=min(timeout, 15)) as resp:
                raw = resp.read(self.config.llm.max_response_bytes + 1)
                if len(raw) > self.config.llm.max_response_bytes:
                    return {
                        "ok": False,
                        "provider": provider,
                        "endpoint": endpoint,
                        "message": "Gateway 响应超过大小限制。",
                        "detail": "",
                    }
                body = raw.decode("utf-8")
                if resp.status >= 400:
                    return {
                        "ok": False,
                        "provider": provider,
                        "endpoint": endpoint,
                        "message": f"Gateway 返回 HTTP {resp.status}，请检查凭据和端点。",
                        "detail": body[:200],
                    }
                try:
                    loads_bounded_json(body)
                except ValueError:
                    return {
                        "ok": False,
                        "provider": provider,
                        "endpoint": endpoint,
                        "message": "Gateway 返回了非 JSON 响应，请确认端点正确。",
                        "detail": body[:200],
                    }
                return {
                    "ok": True,
                    "provider": provider,
                    "endpoint": endpoint,
                    "message": (
                        "Anthropic Gateway 可达，Messages API 返回正常 JSON 响应。"
                        if is_anthropic_messages_endpoint(endpoint)
                        else "Gateway 可达，端点返回正常 JSON 响应。"
                    ),
                    "detail": f"HTTP {resp.status}",
                }
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            return {
                "ok": False,
                "provider": provider,
                "endpoint": endpoint,
                "message": f"Gateway 返回 HTTP {exc.code}，请检查凭据。",
                "detail": body[:200],
            }
        except urllib.error.URLError as exc:
            return {
                "ok": False,
                "provider": provider,
                "endpoint": endpoint,
                "message": f"Gateway 不可达：{exc.reason}",
                "detail": str(exc.reason),
            }
        except OSError as exc:
            return {
                "ok": False,
                "provider": provider,
                "endpoint": endpoint,
                "message": f"网络错误：{exc}",
                "detail": str(exc),
            }

    def reload_llm_defaults(self, payload: dict | None = None) -> dict:
        """Reload the LLM configuration from the config file + environment.

        This reverts any in-memory runtime overrides applied via
        ``update_llm_config`` (e.g. an operator switching to ``ollama`` for a
        live test), restoring the startup defaults such as ``local``.
        """
        with self.lock:
            payload = payload or {}
            if not self.config_path:
                return self.llm_config_payload()
            loaded = load_config(self.config_path)
            loaded.llm.endpoint = _validated_llm_endpoint(
                loaded.llm.provider,
                loaded.llm.endpoint,
                loaded.llm.allowed_hosts,
            )
            self.config.llm = loaded.llm
            self.llm = build_llm(loaded.llm)
            self.orchestrator = Orchestrator(
                self.repo,
                self.normalizer,
                self.memory,
                self.llm,
                self.policy,
                skills=self.skills,
                memory_matcher=MemoryMatcher(self.config.memory_matching),
            )
            actor = str(payload.get("_actor") or "runtime-operator")
            self.repo.set_runtime_setting(
                "llm",
                {
                    "provider": loaded.llm.provider,
                    "endpoint": loaded.llm.endpoint,
                    "model": loaded.llm.model,
                    "timeout_seconds": loaded.llm.timeout_seconds,
                },
                updated_by=actor,
            )
            self.repo.insert_audit(
                new_id("audit"),
                "runtime-config",
                actor,
                "llm_config_reloaded",
                {
                    "provider": loaded.llm.provider,
                    "model": loaded.llm.model,
                    "endpoint_host": urlparse(loaded.llm.endpoint).hostname or "",
                },
            )
            return self.llm_config_payload()

    # ---- runtime syslog intake ---------------------------------------------

    def syslog_config_payload(self) -> dict:
        labels = {"waf": "WAF", "hips": "HIPS", "ndr": "NDR", "rasp": "RASP", "siem": "SIEM"}
        with self.lock:
            active = {
                (item["product"], item["port"], item["protocol"])
                for item in self.syslog_receiver.status()
                if item.get("active")
            }
            configs = []
            for product in sorted(SUPPORTED_PRODUCTS):
                port = int(self.config.syslog.product_ports.get(product, 0))
                protocol = str(self.config.syslog.product_protocols.get(product, "tcp")).lower()
                configs.append(
                    {
                        "product": product,
                        "label": labels.get(product, product.upper()),
                        "port": port,
                        "protocol": protocol if protocol in {"tcp", "udp"} else "tcp",
                        "profile": self.config.syslog.gateway_profiles.get(product, f"{product}-syslog-json"),
                        "saved": (product, port, protocol) in active,
                    }
                )
            return {
                "mode": "embedded" if self.config.syslog.embedded_listeners_enabled else "external_vector",
                "editable": self.config.syslog.embedded_listeners_enabled,
                "recommended_protocol": "tcp",
                "recommendation_reason": "syslog 报文较长时推荐 TCP；UDP 无传输确认，长报文分片后更容易截断或丢包。",
                "configs": configs,
                "listeners": self.syslog_receiver.status(),
            }

    def update_syslog_config(self, payload: dict) -> dict:
        if not self.config.syslog.embedded_listeners_enabled:
            raise ValueError("Syslog is managed by the external Vector deployment")
        product = str(payload.get("product") or "").strip().lower()
        if product not in SUPPORTED_PRODUCTS:
            raise ValueError(f"unsupported product: {product}")
        port = int(payload.get("port", 0))
        if port < 1 or port > 65535:
            raise ValueError("port must be between 1 and 65535")
        protocol = str(payload.get("protocol") or "tcp").strip().lower()
        if protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")

        with self.lock:
            old_product_ports = dict(self.config.syslog.product_ports)
            old_product_protocols = dict(self.config.syslog.product_protocols)
            product_ports = dict(self.config.syslog.product_ports)
            product_protocols = dict(self.config.syslog.product_protocols)
            product_ports[product] = port
            product_protocols[product] = protocol
            seen_ports: dict[int, str] = {}
            for item_product, item_port in product_ports.items():
                item_port = int(item_port)
                if item_port in seen_ports and seen_ports[item_port] != item_product:
                    raise ValueError(f"port {item_port} is already used by {seen_ports[item_port]}")
                seen_ports[item_port] = item_product

            self.config.syslog.product_ports = product_ports
            self.config.syslog.product_protocols = product_protocols
            try:
                self.syslog_receiver.update_product(SyslogListenerSpec(product, port, protocol))
            except Exception:
                self.config.syslog.product_ports = old_product_ports
                self.config.syslog.product_protocols = old_product_protocols
                raise
            actor = str(payload.get("_actor") or "runtime-operator")
            self.repo.set_runtime_setting(
                "syslog",
                {
                    "product_ports": self.config.syslog.product_ports,
                    "product_protocols": self.config.syslog.product_protocols,
                },
                updated_by=actor,
            )
            self.repo.insert_audit(
                new_id("audit"),
                "runtime-config",
                actor,
                "syslog_config_updated",
                {"product": product, "port": port, "protocol": protocol},
            )
            return self.syslog_config_payload()

    # ---- log mapping profiles ----------------------------------------------

    def list_mapping_profiles(self) -> list[dict]:
        with self.lock:
            return self.repo.list_mapping_profiles()

    def get_mapping_profile(self, profile_id: str) -> MappingProfile:
        record = self.repo.get_mapping_profile(profile_id)
        if not record:
            raise ValueError(f"mapping profile not found: {profile_id}")
        profile = MappingProfile.from_dict(record["profile"])
        if not profile.enabled:
            raise ValueError(f"mapping profile disabled: {profile_id}")
        return profile

    def save_mapping_profile(self, payload: dict) -> dict:
        with self.lock:
            profile = MappingProfile.from_dict(payload)
            if not profile.profile_id:
                raise ValueError("profile_id is required")
            if not profile.name:
                profile.name = profile.profile_id
            if not profile.mappings:
                raise ValueError("mappings is required")
            self.repo.save_mapping_profile(mapping_profile_record(profile))
            return self.repo.get_mapping_profile(profile.profile_id) or profile.to_dict()

    def dry_run_mapping_profile(self, payload: dict) -> dict:
        with self.lock:
            profile_payload = payload.get("profile")
            if profile_payload:
                profile = MappingProfile.from_dict(profile_payload)
            else:
                profile_id = str(payload.get("profile_id") or "")
                profile = self.get_mapping_profile(profile_id)
            log = payload.get("log")
            if not isinstance(log, dict):
                raise ValueError("log must be a JSON object")
            return self.log_adapter.dry_run(profile, log)

    def infer_mapping_profile(self, payload: dict) -> dict:
        with self.lock:
            log = payload.get("log")
            if not isinstance(log, dict):
                raise ValueError("log must be a JSON object")
            requested_product = str(payload.get("product") or "").strip().lower()
            if requested_product and requested_product not in SUPPORTED_PRODUCTS:
                raise ValueError(f"unsupported product: {requested_product}")
            detected = self.log_adapter.detect_product(log)
            product = requested_product or str((detected or {}).get("product") or "")
            if product not in SUPPORTED_PRODUCTS:
                raise ValueError("无法自动识别日志产品，请选择 WAF、HIPS、NDR、RASP 或 SIEM 后重试")
            profile_id = str(payload.get("profile_id") or "").strip() or new_id(f"custom-{product}")
            result = self.log_adapter.infer_mapping_profile(log, profile_id, product)
            result["product_detection"] = {
                "product": product,
                "confidence": float((detected or {}).get("confidence") or 0),
                "mode": "manual" if requested_product else "auto",
            }
            return result

    def rasp_sample_log(self) -> dict:
        """Return the canonical RASP vendor-format sample used by the Dashboard
        日志自动适配 "加载示例" button. Sourced from samples_syslog/ so the UI
        example stays in sync with the raw vendor-format samples."""
        return self.sample_log("rasp")

    def sample_log(self, product: str) -> dict:
        product = str(product or "").strip().lower()
        if product not in SUPPORTED_PRODUCTS:
            raise ValueError(f"unsupported product: {product}")
        root = Path(__file__).resolve().parent.parent
        vendor_sample = root / "samples_syslog" / product / f"{product}_alert.json"
        standard_sample = root / "samples" / f"{product}_alert.json"
        siem_case_sample = root / "samples" / "siem_case.json"
        sample_path = vendor_sample if vendor_sample.exists() else standard_sample
        if not sample_path.exists() and product == "siem":
            sample_path = siem_case_sample
        if not sample_path.exists():
            raise ValueError(f"sample log not found for product: {product}")
        return json.loads(sample_path.read_text(encoding="utf-8"))

    def alert_from_payload(self, payload: dict, profile_id: str = "") -> RawAlert:
        if not isinstance(payload, dict):
            raise ValueError("alert body must be a JSON object")
        selected_profile = profile_id or str(payload.get("profile_id") or payload.get("_profile_id") or "")
        if selected_profile:
            log = payload.get("log") if isinstance(payload.get("log"), dict) else payload
            profile = self.get_mapping_profile(selected_profile)
            result = self.log_adapter.adapt(profile, log)
            if not result["ok"]:
                raise ValueError("log mapping failed: " + ", ".join(result["errors"]))
            return result["raw_alert"]

        # 显式带 product 字段的标准告警：走快速路径，按顶层字段构造。
        # 入站 product 视为建议值：若内容指纹识别到不同 product，记审计供复盘
        # （路由可被外部影响，故不盲信顶层 product 字段）。
        declared_product = payload.get("product")
        if declared_product is not None and str(declared_product).strip().lower() not in SUPPORTED_PRODUCTS:
            raise ValueError(
                f"unsupported product: {str(declared_product).strip().lower() or '<empty>'}"
            )
        product = explicit_product(payload)
        if product:
            detected = fingerprint_product(payload)
            if detected and detected != product:
                self.repo.insert_audit(
                    new_id("audit"),
                    new_id("trace"),
                    "gateway",
                    "product_mismatch",
                    {"declared_product": product, "fingerprint_product": detected, "alert_id": payload.get("alert_id") or payload.get("id")},
                )
            return _build_raw_alert(payload, product)

        # 无显式 product 的厂商原生日志：按内容指纹识别 product；若该产品已注册
        # 自动 profile，则套用 profile 做深度字段映射（如 cloudcrasp → auto-rasp-json）。
        detected = fingerprint_product(payload)
        if detected:
            auto_profile_id = AUTO_PROFILE.get(detected)
            if auto_profile_id:
                try:
                    profile = self.get_mapping_profile(auto_profile_id)
                except ValueError:
                    profile = None
                if profile:
                    result = self.log_adapter.adapt(profile, payload)
                    if not result["ok"]:
                        raise ValueError(
                            f"auto profile {auto_profile_id} mapping failed: " + ", ".join(result["errors"])
                        )
                    return result["raw_alert"]
            # 指纹命中但无已注册 profile：落到正确 Subagent（浅字段），而非静默误判为 siem。
            return _build_raw_alert(payload, detected)

        # 看起来是标准告警但漏了 product：保留 siem 兜底（向后兼容）。
        if _looks_like_standard_alert(payload):
            return _build_raw_alert(payload, "siem")

        raise ValueError(
            "无法识别日志来源 product。厂商原生日志请用 ?profile=<id> 提交，"
            "或补全顶层 product 字段（hips/rasp/ndr/waf/siem）。"
        )

    # ---- memory governance (Dashboard 记忆治理 module, architecture §8/§11) ----

    def list_memory(self, filters: dict) -> list[dict]:
        with self.lock:
            include_expired = str(filters.get("include_expired", "")).lower() in {"1", "true", "yes"}
            try:
                limit = int(filters.get("limit", 100))
            except (TypeError, ValueError):
                limit = 100
            limit = max(1, min(limit, 500))
            layer = str(filters.get("layer") or "").strip()
            status = str(filters.get("status") or "").strip()
            if layer and layer not in _MEMORY_LAYERS:
                raise ValueError(f"unsupported memory layer: {layer}")
            if status and status not in _MEMORY_STATUSES:
                raise ValueError(f"unsupported memory status: {status}")
            query = str(filters.get("q") or "").strip()
            if len(query) > 200:
                raise ValueError("memory query is too long")
            return self.repo.query_memory(
                layer=layer or None,
                namespace=filters.get("namespace") or None,
                status=status or None,
                retrieval_key=filters.get("retrieval_key") or None,
                query=query or None,
                limit=limit,
                include_expired=include_expired,
            )

    def memory_summary(self) -> dict:
        with self.lock:
            current = now_ms()
            return self.repo.memory_governance_summary(
                current,
                current - 90 * 24 * 3600 * 1000,
            )

    def memory_detail(self, memory_id: str) -> dict | None:
        with self.lock:
            memory = self.repo.get_memory(memory_id)
            if not memory:
                return None
            detail = dict(memory)
            reasons: list[str] = []
            gates: dict[str, bool] = {}
            if memory["layer"] == LAYER_PRODUCT_LONG_TERM:
                _, reasons = self.memory.promotion_check(
                    memory_id,
                    str(memory.get("approved_by") or ""),
                    str(memory.get("scope") or ""),
                    memory.get("expires_at_ms"),
                )
                failed = {reason.split(":", 1)[0] for reason in reasons}
                gates = {
                    "evidence_traceable": "evidence_traceable" not in failed,
                    "analyst_approved": "analyst_approved" not in failed,
                    "scope_clear": "scope_clear" not in failed,
                    "expiry_set": "expiry_set" not in failed,
                    "no_sensitive_leak": "no_sensitive_leak" not in failed,
                }
            detail["governance"] = {
                "actionable": memory["layer"] == LAYER_PRODUCT_LONG_TERM,
                "gates": gates,
                "reasons": reasons,
                "events": self.repo.list_memory_events(memory_id=memory_id, limit=200),
                "matches": self.repo.list_memory_matches(memory_id=memory_id, limit=200),
            }
            return detail

    def list_memory_events(self, filters: dict) -> list[dict]:
        with self.lock:
            try:
                limit = int(filters.get("limit", 100))
            except (TypeError, ValueError):
                limit = 100
            limit = max(1, min(limit, 500))
            event_type = str(filters.get("event_type") or "").strip()
            if len(event_type) > 100:
                raise ValueError("memory event type is too long")
            return self.repo.list_memory_events(
                memory_id=filters.get("memory_id") or None,
                event_type=event_type or None,
                limit=limit,
            )

    def list_memory_matches(self, filters: dict) -> list[dict]:
        with self.lock:
            try:
                limit = int(filters.get("limit", 100))
            except (TypeError, ValueError):
                limit = 100
            decision = str(filters.get("decision") or "").strip()
            if len(decision) > 100:
                raise ValueError("memory match decision is too long")
            return self.repo.list_memory_matches(
                memory_id=str(filters.get("memory_id") or "").strip() or None,
                event_id=str(filters.get("event_id") or "").strip() or None,
                case_id=str(filters.get("case_id") or "").strip() or None,
                decision=decision or None,
                limit=max(1, min(limit, 500)),
            )

    def promote_memory(self, memory_id: str, body: dict) -> dict:
        with self.lock:
            memory = self._governable_memory(memory_id)
            if memory["status"] not in {STATUS_PENDING, STATUS_QUARANTINED, STATUS_REVOKED, STATUS_EXPIRED}:
                raise ValueError(f"memory status {memory['status']} cannot be promoted")
            approved_by = str(body.get("approved_by") or "").strip()
            scope = str(body.get("scope") or "").strip()
            if len(approved_by) > 500 or len(scope) > 500:
                raise ValueError("approved_by or scope is too long")
            expires_at_ms = self._future_expiry(body.get("expires_at_ms")) if body.get("expires_at_ms") else None
            outcome = self.memory.promote(
                memory_id,
                approved_by=approved_by,
                scope=scope,
                expires_at_ms=expires_at_ms,
                retrieval_key=str(body.get("retrieval_key") or "").strip() or None,
            )
            return {"ok": outcome.ok, "reasons": outcome.reasons, "memory_id": outcome.memory_id}

    def reject_memory(self, memory_id: str, body: dict) -> dict:
        with self.lock:
            memory = self._governable_memory(memory_id)
            if memory["status"] == STATUS_REVOKED:
                raise ValueError("memory is already revoked")
            actor = self._required_memory_text(body, "actor")
            reason = self._required_memory_text(body, "reason")
            self.memory.reject(memory_id, actor, reason)
            return {"ok": True, "memory_id": memory_id}

    def quarantine_memory(self, memory_id: str, body: dict) -> dict:
        with self.lock:
            memory = self._governable_memory(memory_id)
            if memory["status"] == STATUS_QUARANTINED:
                raise ValueError("memory is already quarantined")
            actor = self._required_memory_text(body, "actor")
            reason = self._required_memory_text(body, "reason")
            self.memory.quarantine(memory_id, actor, reason)
            return {"ok": True, "memory_id": memory_id}

    def restore_memory(self, memory_id: str, body: dict) -> dict:
        with self.lock:
            self._governable_memory(memory_id)
            actor = self._required_memory_text(body, "actor")
            reason = self._required_memory_text(body, "reason")
            expiry = body.get("expires_at_ms")
            expires_at_ms = self._future_expiry(expiry) if expiry else None
            outcome = self.memory.restore(memory_id, actor, reason, expires_at_ms)
            restored = self.repo.get_memory(memory_id)
            return {
                "ok": outcome.ok,
                "reasons": outcome.reasons,
                "memory_id": memory_id,
                "status": restored["status"] if restored else "",
            }

    def sweep_memory(self, body: dict) -> dict:
        with self.lock:
            expired = self.memory.expire_due()
            conflicts: list[dict] = []
            products = body.get("products") or sorted(SUPPORTED_PRODUCTS)
            if not isinstance(products, list):
                raise ValueError("products must be a list")
            invalid = [str(product) for product in products if str(product).lower() not in SUPPORTED_PRODUCTS]
            if invalid:
                raise ValueError(f"unsupported products: {', '.join(invalid)}")
            for product in sorted({str(item).lower() for item in products}):
                conflicts.extend(self.memory.detect_conflicts(product))
            return {"expired": expired, "conflicts": conflicts, "products": sorted({str(item).lower() for item in products})}

    def _governable_memory(self, memory_id: str) -> dict:
        memory = self.repo.get_memory(memory_id)
        if not memory:
            raise ValueError("memory not found")
        if memory["layer"] != LAYER_PRODUCT_LONG_TERM:
            raise ValueError("only product long-term memory supports analyst lifecycle actions")
        return memory

    @staticmethod
    def _required_memory_text(body: dict, field: str) -> str:
        value = str(body.get(field) or "").strip()
        if not value:
            raise ValueError(f"{field} is required")
        if len(value) > 500:
            raise ValueError(f"{field} is too long")
        return value

    @staticmethod
    def _future_expiry(value: object) -> int:
        try:
            expiry = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("expires_at_ms must be an integer") from exc
        if expiry <= now_ms():
            raise ValueError("expires_at_ms must be in the future")
        return expiry

    def update_case_disposition(self, case_id: str, body: dict) -> dict | None:
        status = str(body.get("status") or "").strip().lower()
        if status not in _CASE_DISPOSITIONS:
            raise ValueError(f"unsupported case disposition: {status}")
        actor = str(body.get("actor") or "dashboard-analyst").strip() or "dashboard-analyst"
        reason = str(body.get("reason") or "").strip()
        with self.lock:
            with self.repo.transaction():
                updated = self.repo.update_case_status(case_id, status, _commit=False)
                if not updated:
                    return None
                self.repo.insert_audit(
                    new_id("audit"),
                    case_id,
                    actor,
                    _CASE_DISPOSITIONS[status],
                    {
                        "case_id": case_id,
                        "status": status,
                        "reason": reason,
                    },
                    _commit=False,
                )
                return {"ok": True, "case": updated}

    def decide_approval(self, approval_id: str, body: dict) -> dict:
        decision = str(body.get("decision") or "").strip().lower()
        actor = str(body.get("actor") or "").strip()
        reason = str(body.get("reason") or "").strip()
        if decision not in {"approved", "rejected", "cancelled"}:
            raise ValueError(f"unsupported approval decision: {decision}")
        if not actor:
            raise ValueError("approval actor is required")
        if not reason:
            raise ValueError("approval decision reason is required")
        with self.lock:
            existing = self.repo.get_approval(approval_id)
            if not existing:
                raise KeyError("approval not found")
            with self.repo.transaction():
                updated = self.repo.decide_approval(
                    approval_id, decision, actor, reason, _commit=False
                )
                if not updated:
                    raise ValueError("approval is no longer pending")
                self.repo.insert_audit(
                    new_id("audit"),
                    str(updated["case_id"]),
                    actor,
                    (
                        "approval_vote_duplicate"
                        if not updated.get("vote_recorded", True)
                        else "approval_vote_recorded"
                        if updated["status"] == "pending"
                        else "approval_decided"
                    ),
                    {
                        "approval_id": approval_id,
                        "case_id": updated["case_id"],
                        "decision": decision,
                        "reason": reason,
                        "execution_status": "not_executed",
                        "vote_recorded": bool(updated.get("vote_recorded", True)),
                        "vote_count": int(updated.get("vote_count", 0)),
                        "required_approvals": int(updated.get("required_approvals", 1)),
                    },
                    _commit=False,
                )
                return {"ok": True, "approval": updated}

    def confirm_alert_false_positive(self, alert_id: str, body: dict) -> dict:
        with self.lock:
            linked = self.repo.get_linked_alert(alert_id)
            if not linked:
                raise ValueError("alert not found")
            analyst = str(body.get("analyst") or "soc-analyst").strip() or "soc-analyst"
            reason = str(
                body.get("reason") or "人工确认该告警符合业务场景下的误报模式"
            ).strip()
            if len(reason) > 1000:
                raise ValueError("reason is too long")
            expires_at_ms = (
                self._future_expiry(body["expires_at_ms"])
                if body.get("expires_at_ms")
                else None
            )
            # Atomic: the FP memory write and its audit_log row commit together.
            # confirm_business_false_positive opens a nested transaction (no-op
            # commit); the outer block owns the commit including the audit insert.
            with self.repo.transaction():
                outcome = self.memory.confirm_business_false_positive(linked, analyst, reason, expires_at_ms)
                case_id = str(linked.get("case_id") or "")
                disposition = self.repo.set_alert_disposition(
                    alert_id,
                    "false_positive",
                    analyst,
                    reason,
                    _commit=False,
                )
                if not disposition:
                    raise ValueError("alert is not linked to a case")
                if case_id and disposition["case_can_close_as_false_positive"]:
                    self.repo.update_case_status(case_id, "false_positive", _commit=False)
                self.repo.insert_audit(
                    new_id("audit"),
                    str(linked.get("case_id") or alert_id),
                    analyst,
                    "confirm_business_false_positive",
                    {
                        "alert_id": alert_id,
                        "case_id": linked.get("case_id"),
                        "memory_id": outcome["memory_id"],
                        "features": outcome["features"],
                        "reason": reason,
                        "case_closed": bool(disposition["case_can_close_as_false_positive"]),
                        "case_alert_count": disposition["case_alert_count"],
                        "case_false_positive_count": disposition["case_false_positive_count"],
                    },
                    _commit=False,
                )
            return {
                "ok": True,
                "alert_id": alert_id,
                "alert_disposition": disposition,
                "case_closed": bool(disposition["case_can_close_as_false_positive"]),
                **outcome,
            }


class GatewayHandler(BaseHTTPRequestHandler):
    state: GatewayState

    def setup(self):
        super().setup()
        self.connection.settimeout(self.state.config.server.read_timeout_seconds)

    def _security_headers(self, *, static: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
                if static
                else "default-src 'none'; frame-ancestors 'none'"
            ),
        )

    def _json(self, status: int, payload: dict | list):
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    # ---- auth -----------------------------------------------------------

    def _client_is_loopback(self) -> bool:
        host = self.client_address[0] if self.client_address else ""
        if not host:
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _trusted_local_demo_request(self) -> bool:
        return bool(
            self._client_is_loopback()
            and _trusted_loopback_request_headers(
                self.headers.get("Host", ""),
                self.headers.get("Origin", ""),
            )
        )

    def _principal(self) -> dict | None:
        """Resolve a bearer token to a fixed identity and least-privilege roles."""
        auth = self.state.config.auth
        configured = [
            auth.api_token,
            auth.ingest_token,
            auth.operator_token,
            auth.approver_token,
            *(principal.token for principal in auth.principals),
        ]
        header = self.headers.get("Authorization", "")
        token = header[len("Bearer ") :] if header.startswith("Bearer ") else ""
        candidates = [
            (auth.api_token, "api-admin", _ALL_ROLES),
            (auth.ingest_token, "ingest-collector", {_ROLE_INGEST}),
            (auth.operator_token, "soc-operator", {_ROLE_READ, _ROLE_ANALYST, _ROLE_MEMORY}),
            (auth.approver_token, "soc-approver", {_ROLE_READ, _ROLE_APPROVER, _ROLE_MEMORY}),
            *(
                (
                    principal.token,
                    principal.actor,
                    {str(role).strip().lower() for role in principal.roles} & _ALL_ROLES,
                )
                for principal in auth.principals
            ),
        ]
        if any(configured):
            for expected, actor, roles in candidates:
                if expected and token and hmac.compare_digest(token, expected):
                    return {"actor": actor, "roles": set(roles)}
            return None
        if self._trusted_local_demo_request() and auth.allow_loopback_no_token:
            return {"actor": "local-demo-operator", "roles": set(_ALL_ROLES)}
        if (
            not self._client_is_loopback()
            and auth.demo_mode
            and not auth.require_token_when_remote
        ):
            return {"actor": "explicit-demo-operator", "roles": set(_ALL_ROLES)}
        return None

    def _authorized(self) -> bool:
        return self._principal() is not None

    def _require_auth(self) -> bool:
        """Return True if the request is authorized, else send 401."""
        if self._authorized():
            return True
        self.send_response(401)
        data = json.dumps({"error": "unauthorized"}).encode("utf-8")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("WWW-Authenticate", 'Bearer realm="defensive-ai-gateway"')
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)
        return False

    def _require_roles(self, *roles: str) -> bool:
        principal = self._principal()
        if principal is None:
            return self._require_auth()
        if not roles or principal["roles"].intersection(roles):
            return True
        self._json(403, {"error": "forbidden"})
        return False

    def _authenticated_actor(self) -> str:
        principal = self._principal()
        return str(principal["actor"] if principal else "unauthenticated")

    def _is_trusted_demo_sample_request(self) -> bool:
        auth = self.state.config.auth
        configured_tokens = (
            auth.api_token,
            auth.ingest_token,
            auth.operator_token,
            auth.approver_token,
            *(principal.token for principal in auth.principals),
        )
        return bool(
            self._trusted_local_demo_request()
            and auth.allow_loopback_no_token
            and not any(configured_tokens)
            and self.headers.get("X-Defensive-AI-Demo-Sample", "") == "1"
        )

    def _governance_body(self, body: dict, *, actor_field: str = "actor") -> dict:
        governed = dict(body)
        governed[actor_field] = self._authenticated_actor()
        governed["_actor"] = self._authenticated_actor()
        return governed

    def _allow_api_request(self, path: str) -> bool:
        if not path.startswith("/api/") or path in {"/api/health", "/api/live", "/api/ready"}:
            return True
        principal = self._principal()
        peer = self.client_address[0] if self.client_address else "unknown"
        actor = str(principal["actor"] if principal else "unauthenticated")
        key = f"{actor}:{peer}"
        if self.server.allow_api_request(key):
            return True
        self._json(429, {"error": "rate limit exceeded"})
        return False

    # ---- body / errors --------------------------------------------------

    def _read_json(self) -> dict:
        transfer_encoding = self.headers.get_all("Transfer-Encoding") or []
        if any(value.strip() for value in transfer_encoding):
            # This server deliberately implements Content-Length framing only.
            # Accepting a second framing scheme invites proxy/parser disagreement.
            self.close_connection = True
            raise ValueError("Transfer-Encoding is not supported")
        content_lengths = self.headers.get_all("Content-Length") or []
        if len(content_lengths) > 1:
            self.close_connection = True
            raise ValueError("duplicate Content-Length headers are not allowed")
        raw_length = content_lengths[0] if content_lengths else "0"
        # RFC framing accepts decimal digits only. ``int`` would also accept
        # signs and surrounding whitespace, which some upstream proxies reject
        # or interpret differently.
        if not raw_length.isascii() or not raw_length.isdecimal():
            self.close_connection = True
            raise ValueError("invalid Content-Length")
        try:
            length = int(raw_length)
        except (TypeError, ValueError) as exc:
            # Do not leave an unframed body on a persistent connection: it could
            # be interpreted as the start of a later HTTP request.
            self.close_connection = True
            raise ValueError("invalid Content-Length") from exc
        # A negative Content-Length must not turn into ``read(-1)`` or leave an
        # unframed body on a persistent connection.
        if length < 0:
            self.close_connection = True
            raise ValueError("Content-Length must not be negative")
        if length > MAX_BODY_BYTES:
            # Drain at most the permitted body size before closing. This lets a
            # normal client finish writing and receive its 413, while the short
            # socket timeout bounds a peer that advertises a huge body but sends
            # it slowly. Closing prevents any remaining bytes from becoming a
            # later HTTP request on this connection.
            self.close_connection = True
            original_timeout = self.connection.gettimeout()
            try:
                self.connection.settimeout(0.25)
                self.rfile.read(MAX_BODY_BYTES)
            except OSError:
                pass
            finally:
                self.connection.settimeout(original_timeout)
            raise _PayloadTooLarge()
        media_type = self.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if media_type != "application/json":
            # Closing prevents the unread simple-request body from being parsed
            # as another request on a persistent connection. Requiring JSON also
            # turns cross-origin browser writes into CORS-preflighted requests.
            self.close_connection = True
            raise _UnsupportedMediaType("Content-Type must be application/json")
        try:
            raw = self.rfile.read(length) if length > 0 else b""
        except (TimeoutError, socket.timeout) as exc:
            self.close_connection = True
            raise ValueError("request body timed out") from exc
        if not raw:
            return {}
        payload = loads_bounded_json(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        return payload

    def _client_error(self, exc: Exception) -> None:
        status = 415 if isinstance(exc, _UnsupportedMediaType) else 400
        self._json(status, {"error": str(exc)})

    def _server_error(self, exc: Exception) -> None:
        # Never leak internal exception text (paths/SQL/stack) to the client; log it.
        print(f"[gateway] internal error: {exc!r}")
        self._json(500, {"error": "internal server error"})

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if not self._allow_api_request(parsed.path):
            return
        if parsed.path == "/api/live":
            self._json(200, {"ok": True, "status": "live"})
            return
        if parsed.path in {"/api/health", "/api/ready"}:
            readiness = self.state.readiness()
            payload = {
                "ok": bool(readiness["ok"]),
                "status": "ready" if readiness["ok"] else "not_ready",
            }
            principal = self._principal()
            if principal is not None and principal["roles"].intersection(
                {_ROLE_READ, _ROLE_CONFIG}
            ):
                payload.update(
                    {
                        "checks": readiness["checks"],
                        "stats": self.state.repo.stats(),
                        "processing": self.state.processing_stats(),
                    }
                )
            self._json(200 if readiness["ok"] else 503, payload)
            return
        if parsed.path == "/api/samples/rasp-alert":
            self._json(200, self.state.rasp_sample_log())
            return
        if parsed.path.startswith("/api/samples/") and parsed.path.endswith("-alert"):
            product = parsed.path.rsplit("/", 1)[-1][: -len("-alert")]
            try:
                self._json(200, self.state.sample_log(product))
            except ValueError as exc:
                self._json(404, {"error": str(exc)})
            return
        if parsed.path == "/api/session":
            if not self._require_auth():
                return
            principal = self._principal() or {"actor": "", "roles": set()}
            self._json(
                200,
                {"actor": principal["actor"], "roles": sorted(principal["roles"])},
            )
            return
        if parsed.path in ("/api/config/llm", "/api/config/llm/models"):
            # Sensitive: exposes provider/endpoint and probes the LLM backend.
            if not self._require_roles(_ROLE_CONFIG):
                return
            if parsed.path == "/api/config/llm":
                self._json(200, self.state.llm_config_payload())
                return
            endpoint = parse_qs(parsed.query).get("endpoint", [""])[0]
            self._json(200, self.state.list_ollama_models(endpoint))
            return
        if parsed.path == "/api/config/syslog":
            if not self._require_roles(_ROLE_CONFIG):
                return
            self._json(200, self.state.syslog_config_payload())
            return
        if parsed.path == "/api/mapping-profiles":
            if not self._require_roles(_ROLE_READ, _ROLE_CONFIG, _ROLE_ANALYST):
                return
            self._json(200, {"profiles": self.state.list_mapping_profiles()})
            return
        if parsed.path == "/api/skills":
            if not self._require_roles(_ROLE_READ, _ROLE_CONFIG, _ROLE_ANALYST):
                return
            self._json(200, {"skills": self.state.skills.list()})
            return
        if parsed.path == "/api/approvals":
            if not self._require_roles(_ROLE_READ, _ROLE_APPROVER):
                return
            query = parse_qs(parsed.query)
            self._json(
                200,
                {
                    "approvals": self.state.repo.list_approvals(
                        case_id=_query_first(query, "case_id") or None,
                        status=_query_first(query, "status") or None,
                        limit=_query_int(query, "limit", 100, min_value=1, max_value=500),
                    )
                },
            )
            return
        if parsed.path == "/api/alerts/inbox":
            if not self._require_roles(_ROLE_READ):
                return
            query = parse_qs(parsed.query)
            status = _query_first(query, "status") or None
            allowed = {"pending", "retry", "processing", "completed", "dead_letter"}
            if status and status not in allowed:
                self._json(400, {"error": f"unsupported inbox status: {status}"})
                return
            self._json(
                200,
                {
                    "stats": self.state.repo.inbox_stats(),
                    "alerts": self.state.repo.list_inbox_alerts(
                        status=status,
                        limit=_query_int(query, "limit", 100, min_value=1, max_value=500),
                    ),
                },
            )
            return
        if parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/inbox"):
            if not self._require_roles(_ROLE_READ):
                return
            alert_id = unquote(parsed.path.split("/")[-2])
            record = self.state.repo.get_inbox_alert(alert_id)
            if not record:
                self._json(404, {"error": "inbox alert not found"})
                return
            self._json(200, record)
            return
        if parsed.path.startswith("/api/mapping-profiles/"):
            if not self._require_roles(_ROLE_READ, _ROLE_CONFIG, _ROLE_ANALYST):
                return
            profile_id = parsed.path.rsplit("/", 1)[-1]
            record = self.state.repo.get_mapping_profile(profile_id)
            if not record:
                self._json(404, {"error": "mapping profile not found"})
                return
            self._json(200, record)
            return
        if parsed.path == "/api/cases":
            if not self._require_roles(_ROLE_READ, _ROLE_ANALYST, _ROLE_APPROVER):
                return
            query = parse_qs(parsed.query)
            limit = _query_int(query, "limit", 50, min_value=1, max_value=500)
            self._json(
                200,
                {
                    "cases": self.state.repo.list_cases(
                        limit=limit,
                        product=_query_first(query, "product") or None,
                        severity=_query_first(query, "severity") or None,
                        status=_query_first(query, "status") or None,
                        active_only=_query_first(query, "active_only").lower() in {"1", "true", "yes"},
                        created_from_ms=_query_optional_int(query, "created_from_ms"),
                        created_to_ms=_query_optional_int(query, "created_to_ms"),
                    )
                },
            )
            return
        if parsed.path.startswith("/api/cases/") and "/details/" in parsed.path:
            if not self._require_roles(_ROLE_READ, _ROLE_ANALYST, _ROLE_APPROVER):
                return
            parts = parsed.path.split("/")
            if len(parts) != 6 or parts[4] != "details":
                self._json(404, {"error": "case detail endpoint not found"})
                return
            case_id = unquote(parts[3])
            section = unquote(parts[5])
            if not case_id or section not in _CASE_DETAIL_SECTIONS:
                self._json(404, {"error": "case detail endpoint not found"})
                return
            case_data = self.state.repo.get_case(case_id)
            if not case_data:
                self._json(404, {"error": "case not found"})
                return
            self._json(200, _case_detail_section_payload(case_data, section))
            return
        if parsed.path.startswith("/api/cases/"):
            if not self._require_roles(_ROLE_READ, _ROLE_ANALYST, _ROLE_APPROVER):
                return
            case_id = unquote(parsed.path.rsplit("/", 1)[-1])
            case_data = self.state.repo.get_case(case_id)
            if not case_data:
                self._json(404, {"error": "case not found"})
                return
            self._json(200, case_data)
            return
        if parsed.path == "/api/memory/summary":
            if not self._require_roles(_ROLE_READ, _ROLE_MEMORY):
                return
            self._json(200, self.state.memory_summary())
            return
        if parsed.path == "/api/memory":
            if not self._require_roles(_ROLE_READ, _ROLE_MEMORY):
                return
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            try:
                self._json(200, {"memories": self.state.list_memory(query)})
            except ValueError as exc:
                self._client_error(exc)
            return
        if parsed.path == "/api/memory/events":
            if not self._require_roles(_ROLE_READ, _ROLE_MEMORY):
                return
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            try:
                self._json(200, {"events": self.state.list_memory_events(query)})
            except ValueError as exc:
                self._client_error(exc)
            return
        if parsed.path == "/api/memory/matches":
            if not self._require_roles(_ROLE_READ, _ROLE_MEMORY):
                return
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            try:
                self._json(200, {"matches": self.state.list_memory_matches(query)})
            except ValueError as exc:
                self._client_error(exc)
            return
        if parsed.path.startswith("/api/memory/"):
            if not self._require_roles(_ROLE_READ, _ROLE_MEMORY):
                return
            memory_id = unquote(parsed.path.rsplit("/", 1)[-1])
            memory = self.state.memory_detail(memory_id)
            if not memory:
                self._json(404, {"error": "memory not found"})
                return
            self._json(200, memory)
            return
        if parsed.path.startswith("/api/"):
            if not self._require_auth():
                return
            self._json(404, {"error": "not found"})
            return
        self._serve_static(parsed.path)

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        if not self._allow_api_request(parsed.path):
            return
        if parsed.path.startswith("/api/config/"):
            authorized = self._require_roles(_ROLE_CONFIG)
        elif parsed.path == "/api/mapping-profiles":
            authorized = self._require_roles(_ROLE_CONFIG)
        elif parsed.path.startswith("/api/mapping-profiles/"):
            authorized = self._require_roles(_ROLE_ANALYST, _ROLE_CONFIG)
        elif parsed.path.startswith("/api/memory/"):
            authorized = self._require_roles(_ROLE_MEMORY)
        elif parsed.path.startswith("/api/cases/"):
            authorized = self._require_roles(_ROLE_ANALYST)
        elif parsed.path.startswith("/api/approvals/"):
            authorized = self._require_roles(_ROLE_APPROVER)
        elif parsed.path.endswith("/confirm-false-positive"):
            authorized = self._require_roles(_ROLE_ANALYST, _ROLE_MEMORY)
        elif parsed.path == "/api/alerts":
            authorized = self._require_roles(_ROLE_INGEST)
        else:
            authorized = self._require_auth()
        if not authorized:
            return
        if parsed.path == "/api/config/llm":
            try:
                updated = self.state.update_llm_config(self._governance_body(self._read_json()))
                self._json(200, {"ok": True, "llm": updated})
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path == "/api/config/llm/reload":
            try:
                reloaded = self.state.reload_llm_defaults(
                    self._governance_body(self._read_json())
                )
                self._json(200, {"ok": True, "llm": reloaded})
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path == "/api/config/llm/test":
            try:
                result = self.state.test_llm_connection(self._read_json())
                self._json(200, result)
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path == "/api/config/syslog":
            try:
                updated = self.state.update_syslog_config(self._governance_body(self._read_json()))
                self._json(200, {"ok": True, "syslog": updated})
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path == "/api/mapping-profiles":
            try:
                saved = self.state.save_mapping_profile(self._read_json())
                self._json(200, {"ok": True, "profile": saved})
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path == "/api/mapping-profiles/dry-run":
            try:
                self._json(200, self.state.dry_run_mapping_profile(self._read_json()))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path == "/api/mapping-profiles/infer":
            try:
                self._json(200, self.state.infer_mapping_profile(self._read_json()))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path == "/api/memory/sweep":
            try:
                self._json(200, self.state.sweep_memory(self._read_json()))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path.startswith("/api/memory/") and parsed.path.endswith("/promote"):
            memory_id = parsed.path.split("/")[-2]
            try:
                self._json(200, self.state.promote_memory(memory_id, self._governance_body(self._read_json(), actor_field="approved_by")))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path.startswith("/api/memory/") and parsed.path.endswith("/reject"):
            memory_id = parsed.path.split("/")[-2]
            try:
                self._json(200, self.state.reject_memory(memory_id, self._governance_body(self._read_json())))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path.startswith("/api/memory/") and parsed.path.endswith("/quarantine"):
            memory_id = parsed.path.split("/")[-2]
            try:
                self._json(200, self.state.quarantine_memory(memory_id, self._governance_body(self._read_json())))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path.startswith("/api/memory/") and parsed.path.endswith("/restore"):
            memory_id = unquote(parsed.path.split("/")[-2])
            try:
                self._json(200, self.state.restore_memory(memory_id, self._governance_body(self._read_json())))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path.startswith("/api/cases/") and parsed.path.endswith("/disposition"):
            case_id = unquote(parsed.path.split("/")[-2])
            try:
                updated = self.state.update_case_disposition(case_id, self._governance_body(self._read_json()))
                if not updated:
                    self._json(404, {"error": "case not found"})
                else:
                    self._json(200, updated)
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path.startswith("/api/approvals/") and parsed.path.endswith("/decision"):
            approval_id = unquote(parsed.path.split("/")[-2])
            try:
                self._json(200, self.state.decide_approval(approval_id, self._governance_body(self._read_json())))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except KeyError:
                self._json(404, {"error": "approval not found"})
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/confirm-false-positive"):
            alert_id = unquote(parsed.path.split("/")[-2])
            try:
                self._json(200, self.state.confirm_alert_false_positive(alert_id, self._governance_body(self._read_json(), actor_field="analyst")))
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path != "/api/alerts":
            self._json(404, {"error": "not found"})
            return
        try:
            payload = self._read_json()
            profile_id = parse_qs(parsed.query).get("profile", [""])[0]
            alert = self.state.alert_from_payload(payload, profile_id)
            if self._is_trusted_demo_sample_request():
                alert.trusted_sample = True
            result = self.state.submit_alert(alert)
            self._json(202, result)
        except _PayloadTooLarge:
            self._json(413, {"error": "request body too large"})
        except AlertQueueFull as exc:
            self._json(429, {"error": str(exc), "processing": self.state.processing_stats()})
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self._client_error(exc)
        except Exception as exc:  # pragma: no cover - surfaced to local operator
            self._server_error(exc)

    def do_HEAD(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.send_response(405)
            self.send_header("Allow", "GET")
            self.send_header("Content-Length", "0")
            self._security_headers()
            self.end_headers()
            return
        self._serve_static(parsed.path, head_only=True)

    def _serve_static(self, path: str, *, head_only: bool = False):
        static_dir = (Path(__file__).parent / "static").resolve()
        if path in {"", "/"}:
            target = static_dir / "index.html"
        else:
            target = static_dir / path.lstrip("/")
        # Path-traversal guard: resolved target must stay inside static_dir.
        try:
            resolved = target.resolve()
        except (OSError, ValueError):
            self._json(404, {"error": "not found"})
            return
        if not resolved.is_relative_to(static_dir) or not resolved.is_file():
            self._json(404, {"error": "not found"})
            return
        content = resolved.read_bytes()
        mime = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        # Assets are not content-hashed, so force revalidation after upgrades
        # rather than letting a browser retain an incompatible JS/CSS version.
        self.send_header("Cache-Control", "no-cache")
        self._security_headers(static=True)
        self.end_headers()
        if not head_only:
            self.wfile.write(content)

    def log_message(self, fmt: str, *args):
        print(f"[gateway] {self.address_string()} {fmt % args}")


class GatewayHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, request_handler_class, state: GatewayState):
        self.state = state
        self._connection_slots = threading.BoundedSemaphore(state.config.server.max_connections)
        self._rate_lock = threading.Lock()
        self._rate_windows: dict[str, tuple[int, int]] = {}
        super().__init__(server_address, request_handler_class)

    def allow_api_request(self, key: str) -> bool:
        minute = int(time.monotonic() // 60)
        with self._rate_lock:
            window, count = self._rate_windows.get(key, (minute, 0))
            if window != minute:
                window, count = minute, 0
            count += 1
            self._rate_windows[key] = (window, count)
            if len(self._rate_windows) > 10_000:
                self._rate_windows = {
                    item_key: value for item_key, value in self._rate_windows.items() if value[0] == minute
                }
            return count <= self.state.config.server.requests_per_minute

    def process_request(self, request, client_address):  # noqa: ANN001
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):  # noqa: ANN001
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def server_close(self):
        self.state.stop()
        super().server_close()


def build_server(config: GatewayConfig, config_path: str = "") -> ThreadingHTTPServer:
    _validate_exposed_server_config(config)
    state = GatewayState(config, config_path=config_path)
    handler_class = type("GatewayHandler", (GatewayHandler,), {"state": state})
    try:
        return GatewayHTTPServer((config.server.host, config.server.port), handler_class, state)
    except Exception:
        state.stop()
        raise


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Defensive AI Gateway")
    parser.add_argument("--config", default="config/dev.yaml")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    server = build_server(config, config_path=args.config)
    print(f"Defensive AI Gateway listening on http://{config.server.host}:{config.server.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Defensive AI Gateway shutting down")
    finally:
        server.server_close()
