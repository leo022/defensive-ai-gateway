from __future__ import annotations

import argparse
import hmac
import json
import mimetypes
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .config import GatewayConfig, LLMConfig, load_config
from .database import Repository
from .log_adapter import (
    AUTO_PROFILE,
    LogAdapter,
    MappingProfile,
    SUPPORTED_PRODUCTS,
    default_mapping_profile,
    demo_rasp_profile,
    explicit_product,
    fingerprint_product,
    mapping_profile_record,
)
from .llm import build_llm
from .memory import MemoryManager
from .models import RawAlert, new_id
from .normalizer import EventNormalizer
from .orchestrator import Orchestrator
from .policy import PolicyEngine
from .processing import AlertProcessor, AlertQueueFull
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

_CASE_DISPOSITIONS = {
    "under_review": "escalate_case_review",
    "confirmed_attack": "confirm_case_attack",
    "closed": "close_case",
    "open": "reopen_case",
}


class _PayloadTooLarge(Exception):
    """Raised when an inbound body exceeds ``MAX_BODY_BYTES``."""


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
        self.policy = PolicyEngine(config.policy)
        self.normalizer = EventNormalizer(self.policy)
        self.memory = MemoryManager(self.repo, self.policy)
        self.llm = build_llm(config.llm)
        self.log_adapter = LogAdapter(self.normalizer)
        self._seed_mapping_profiles()
        self.orchestrator = Orchestrator(self.repo, self.normalizer, self.memory, self.llm, self.policy)
        self.syslog_receiver = SyslogReceiverManager(config.server.host, self._handle_syslog_message)
        self.alert_processor = (
            AlertProcessor(
                self._handle_queued_alert,
                max_size=config.processing.queue_max_size,
                workers=config.processing.workers,
            )
            if config.processing.async_enabled
            else None
        )
        if self.alert_processor:
            self.alert_processor.start()

    def _handle_queued_alert(self, alert: RawAlert):
        return self.orchestrator.handle_alert(alert)

    def stop_alert_processor(self) -> None:
        if self.alert_processor:
            self.alert_processor.stop()

    def stop(self) -> None:
        self.syslog_receiver.stop()
        self.stop_alert_processor()

    def _handle_syslog_message(self, spec: SyslogListenerSpec, data: bytes, peer: str) -> None:
        with self.lock:
            router = SyslogPortRouter(self.config.syslog.product_ports, self.config.syslog.gateway_profiles)
            routed = router.route(spec.port, data, hostname=peer, appname=spec.product)
            alert = self.alert_from_payload(routed.payload, routed.profile_id)
        self.submit_alert(alert)

    def processing_stats(self) -> dict:
        if not self.alert_processor:
            return {
                "enabled": False,
                "queue_max_size": 0,
                "workers": 0,
                "queued": 0,
                "inflight": 0,
                "submitted": 0,
                "processed": 0,
                "failed": 0,
                "rejected": 0,
            }
        return self.alert_processor.stats().to_dict()

    def submit_alert(self, alert: RawAlert) -> dict:
        if self.alert_processor:
            self.alert_processor.submit(alert)
            return {
                "ok": True,
                "status": "queued",
                "alert_id": alert.alert_id,
                "product": alert.product,
                "queue": self.processing_stats(),
            }
        result = self.orchestrator.handle_alert(alert)
        return result.to_dict()

    def _seed_mapping_profiles(self) -> None:
        self.repo.delete_mapping_profile("demo-waf-json")
        for profile in [default_mapping_profile(), demo_rasp_profile()]:
            if not self.repo.get_mapping_profile(profile.profile_id):
                self.repo.save_mapping_profile(mapping_profile_record(profile))

    def llm_config_payload(self) -> dict:
        with self.lock:
            llm = self.config.llm
            return {
                "provider": llm.provider,
                "endpoint": llm.endpoint,
                "api_key_env": llm.api_key_env,
                "api_key_set": bool(llm.api_key),
                "model": llm.model,
                "timeout_seconds": llm.timeout_seconds,
            }

    def update_llm_config(self, payload: dict) -> dict:
        with self.lock:
            current = self.config.llm
            api_key = str(payload.get("api_key", ""))
            if not api_key and payload.get("keep_existing_key", True):
                api_key = current.api_key
            updated = LLMConfig(
                provider=str(payload.get("provider", current.provider)).strip() or current.provider,
                endpoint=str(payload.get("endpoint", current.endpoint)).strip(),
                api_key_env=str(payload.get("api_key_env", current.api_key_env)).strip() or current.api_key_env,
                api_key=api_key,
                model=str(payload.get("model", current.model)).strip() or current.model,
                timeout_seconds=int(payload.get("timeout_seconds", current.timeout_seconds)),
            )
            self.config.llm = updated
            self.llm = build_llm(updated)
            self.orchestrator = Orchestrator(self.repo, self.normalizer, self.memory, self.llm, self.policy)
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
        tags_url = _ollama_tags_url(endpoint)
        # SSRF guard: the model picker may only reach a local Ollama instance.
        host = (urlparse(tags_url).hostname or "").lower()
        if host not in _ALLOWED_OLLAMA_HOSTS:
            return {
                "ok": False,
                "provider": provider,
                "endpoint": tags_url,
                "models": [],
                "error": f"refused: host '{host}' is not in the local Ollama allowlist",
            }
        try:
            req = urllib.request.Request(tags_url, headers={"Accept": "application/json"}, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
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

    def reload_llm_defaults(self) -> dict:
        """Reload the LLM configuration from the config file + environment.

        This reverts any in-memory runtime overrides applied via
        ``update_llm_config`` (e.g. an operator switching to ``ollama`` for a
        live test), restoring the startup defaults such as ``local``.
        """
        with self.lock:
            if not self.config_path:
                return self.llm_config_payload()
            config = load_config(self.config_path)
            self.config = config
            self.llm = build_llm(config.llm)
            self.orchestrator = Orchestrator(self.repo, self.normalizer, self.memory, self.llm, self.policy)
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
                "recommended_protocol": "tcp",
                "recommendation_reason": "syslog 报文较长时推荐 TCP；UDP 无传输确认，长报文分片后更容易截断或丢包。",
                "configs": configs,
                "listeners": self.syslog_receiver.status(),
            }

    def update_syslog_config(self, payload: dict) -> dict:
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
            product = str(payload.get("product") or "rasp").strip().lower() or "rasp"
            if product not in SUPPORTED_PRODUCTS:
                raise ValueError(f"unsupported product: {product}")
            profile_id = str(payload.get("profile_id") or f"auto-{product}-json").strip() or f"auto-{product}-json"
            return self.log_adapter.infer_mapping_profile(log, profile_id, product)

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
            return self.repo.query_memory(
                layer=filters.get("layer") or None,
                namespace=filters.get("namespace") or None,
                status=filters.get("status") or None,
                retrieval_key=filters.get("retrieval_key") or None,
                limit=limit,
                include_expired=include_expired,
            )

    def list_memory_events(self, filters: dict) -> list[dict]:
        with self.lock:
            try:
                limit = int(filters.get("limit", 100))
            except (TypeError, ValueError):
                limit = 100
            return self.repo.list_memory_events(
                memory_id=filters.get("memory_id") or None,
                event_type=filters.get("event_type") or None,
                limit=limit,
            )

    def promote_memory(self, memory_id: str, body: dict) -> dict:
        with self.lock:
            outcome = self.memory.promote(
                memory_id,
                approved_by=str(body.get("approved_by", "")),
                scope=str(body.get("scope", "")),
                expires_at_ms=int(body["expires_at_ms"]) if body.get("expires_at_ms") else None,
                retrieval_key=body.get("retrieval_key"),
            )
            return {"ok": outcome.ok, "reasons": outcome.reasons, "memory_id": outcome.memory_id}

    def reject_memory(self, memory_id: str, body: dict) -> dict:
        with self.lock:
            self.memory.reject(memory_id, str(body.get("actor", "analyst")), str(body.get("reason", "")))
            return {"ok": True, "memory_id": memory_id}

    def quarantine_memory(self, memory_id: str, body: dict) -> dict:
        with self.lock:
            self.memory.quarantine(memory_id, str(body.get("actor", "analyst")), str(body.get("reason", "")))
            return {"ok": True, "memory_id": memory_id}

    def sweep_memory(self, body: dict) -> dict:
        with self.lock:
            expired = self.memory.expire_due()
            conflicts: list[dict] = []
            for product in body.get("products", []) or []:
                conflicts.extend(self.memory.detect_conflicts(product))
            return {"expired": expired, "conflicts": conflicts}

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

    def confirm_alert_false_positive(self, alert_id: str, body: dict) -> dict:
        with self.lock:
            linked = self.repo.get_linked_alert(alert_id)
            if not linked:
                raise ValueError("alert not found")
            analyst = str(body.get("analyst") or "soc-analyst")
            reason = str(body.get("reason") or "人工确认该告警符合业务场景下的误报模式")
            expires_at_ms = int(body["expires_at_ms"]) if body.get("expires_at_ms") else None
            # Atomic: the FP memory write and its audit_log row commit together.
            # confirm_business_false_positive opens a nested transaction (no-op
            # commit); the outer block owns the commit including the audit insert.
            with self.repo.transaction():
                outcome = self.memory.confirm_business_false_positive(linked, analyst, reason, expires_at_ms)
                case_id = str(linked.get("case_id") or "")
                if case_id:
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
                    },
                    _commit=False,
                )
            return {"ok": True, "alert_id": alert_id, **outcome}


class GatewayHandler(BaseHTTPRequestHandler):
    state: GatewayState

    def _json(self, status: int, payload: dict | list):
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---- auth -----------------------------------------------------------

    def _client_is_loopback(self) -> bool:
        host = self.client_address[0] if self.client_address else ""
        return host in {"127.0.0.1", "::1", ""}

    def _authorized(self) -> bool:
        """Authorize a request against the configured shared bearer token.

        - If a token is configured, the request must carry ``Authorization: Bearer
          <token>`` (constant-time compare).
        - If no token is configured, loopback clients are accepted (dev/tests);
          non-loopback clients are rejected when ``require_token_when_remote``.
        """
        auth = self.state.config.auth
        if auth.api_token:
            header = self.headers.get("Authorization", "")
            expected = f"Bearer {auth.api_token}"
            return hmac.compare_digest(header, expected)
        if self._client_is_loopback():
            return auth.allow_loopback_no_token
        return not auth.require_token_when_remote

    def _require_auth(self) -> bool:
        """Return True if the request is authorized, else send 401."""
        if self._authorized():
            return True
        self._json(401, {"error": "unauthorized"})
        return False

    # ---- body / errors --------------------------------------------------

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        # Clamp negatives: a Content-Length of -1 would otherwise make
        # rfile.read(-1) read until EOF (unbounded memory). Treat as empty.
        if length < 0:
            length = 0
        if length > MAX_BODY_BYTES:
            # Reject without reading the (potentially gigantic) body. We cap the
            # drain at MAX_BODY_BYTES so a hostile Content-Length can't pin a
            # worker reading forever; the connection is then closed by the server.
            remaining = MAX_BODY_BYTES
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            raise _PayloadTooLarge()
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _client_error(self, exc: Exception) -> None:
        self._json(400, {"error": str(exc)})

    def _server_error(self, exc: Exception) -> None:
        # Never leak internal exception text (paths/SQL/stack) to the client; log it.
        print(f"[gateway] internal error: {exc!r}")
        self._json(500, {"error": "internal server error"})

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json(200, {"ok": True, "stats": self.state.repo.stats(), "processing": self.state.processing_stats()})
            return
        if parsed.path in ("/api/config/llm", "/api/config/llm/models"):
            # Sensitive: exposes provider/endpoint and probes the LLM backend.
            if not self._require_auth():
                return
            if parsed.path == "/api/config/llm":
                self._json(200, self.state.llm_config_payload())
                return
            endpoint = parse_qs(parsed.query).get("endpoint", [""])[0]
            self._json(200, self.state.list_ollama_models(endpoint))
            return
        if parsed.path == "/api/config/syslog":
            if not self._require_auth():
                return
            self._json(200, self.state.syslog_config_payload())
            return
        if parsed.path == "/api/mapping-profiles":
            self._json(200, {"profiles": self.state.list_mapping_profiles()})
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
        if parsed.path.startswith("/api/mapping-profiles/"):
            profile_id = parsed.path.rsplit("/", 1)[-1]
            record = self.state.repo.get_mapping_profile(profile_id)
            if not record:
                self._json(404, {"error": "mapping profile not found"})
                return
            self._json(200, record)
            return
        if parsed.path == "/api/cases":
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
                        created_from_ms=_query_optional_int(query, "created_from_ms"),
                        created_to_ms=_query_optional_int(query, "created_to_ms"),
                    )
                },
            )
            return
        if parsed.path.startswith("/api/cases/"):
            case_id = unquote(parsed.path.rsplit("/", 1)[-1])
            case_data = self.state.repo.get_case(case_id)
            if not case_data:
                self._json(404, {"error": "case not found"})
                return
            self._json(200, case_data)
            return
        if parsed.path == "/api/memory":
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            self._json(200, {"memories": self.state.list_memory(query)})
            return
        if parsed.path == "/api/memory/events":
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            self._json(200, {"events": self.state.list_memory_events(query)})
            return
        if parsed.path.startswith("/api/memory/"):
            memory_id = parsed.path.rsplit("/", 1)[-1]
            memory = self.state.repo.get_memory(memory_id)
            if not memory:
                self._json(404, {"error": "memory not found"})
                return
            self._json(200, memory)
            return
        self._serve_static(parsed.path)

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        # Every mutating endpoint requires authentication.
        if not self._require_auth():
            return
        if parsed.path == "/api/config/llm":
            try:
                updated = self.state.update_llm_config(self._read_json())
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
                reloaded = self.state.reload_llm_defaults()
                self._json(200, {"ok": True, "llm": reloaded})
            except _PayloadTooLarge:
                self._json(413, {"error": "request body too large"})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self._client_error(exc)
            except Exception as exc:
                self._server_error(exc)
            return
        if parsed.path == "/api/config/syslog":
            try:
                updated = self.state.update_syslog_config(self._read_json())
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
                self._json(200, self.state.promote_memory(memory_id, self._read_json()))
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
                self._json(200, self.state.reject_memory(memory_id, self._read_json()))
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
                self._json(200, self.state.quarantine_memory(memory_id, self._read_json()))
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
                updated = self.state.update_case_disposition(case_id, self._read_json())
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
        if parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/confirm-false-positive"):
            alert_id = unquote(parsed.path.split("/")[-2])
            try:
                self._json(200, self.state.confirm_alert_false_positive(alert_id, self._read_json()))
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

    def _serve_static(self, path: str):
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
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, fmt: str, *args):
        print(f"[gateway] {self.address_string()} {fmt % args}")


class GatewayHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, request_handler_class, state: GatewayState):
        self.state = state
        super().__init__(server_address, request_handler_class)

    def server_close(self):
        self.state.stop()
        super().server_close()


def build_server(config: GatewayConfig, config_path: str = "") -> ThreadingHTTPServer:
    state = GatewayState(config, config_path=config_path)
    handler_class = type("GatewayHandler", (GatewayHandler,), {"state": state})
    return GatewayHTTPServer((config.server.host, config.server.port), handler_class, state)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Defensive AI Gateway")
    parser.add_argument("--config", default="config/dev.yaml")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    server = build_server(config, config_path=args.config)
    print(f"Defensive AI Gateway listening on http://{config.server.host}:{config.server.port}")
    server.serve_forever()
