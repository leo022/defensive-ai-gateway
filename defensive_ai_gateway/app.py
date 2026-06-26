from __future__ import annotations

import argparse
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


_STANDARD_ALERT_KEYS = ("event_type", "severity", "alert_id", "source", "timestamp")


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


class GatewayState:
    def __init__(self, config: GatewayConfig):
        self.config = config
        self.lock = threading.RLock()
        self.repo = Repository(config.database.path)
        self.policy = PolicyEngine(config.policy)
        self.normalizer = EventNormalizer(self.policy)
        self.memory = MemoryManager(self.repo, self.policy)
        self.llm = build_llm(config.llm)
        self.log_adapter = LogAdapter(self.normalizer)
        self._seed_mapping_profiles()
        self.orchestrator = Orchestrator(self.repo, self.normalizer, self.memory, self.llm, self.policy)

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

    def list_ollama_models(self) -> dict:
        """List models available in the local Ollama instance.

        Derives the Ollama ``/api/tags`` URL from the configured LLM endpoint
        so the dashboard can offer a model picker instead of a free-text field.
        """
        with self.lock:
            llm = self.config.llm
            provider = llm.provider
            endpoint = llm.endpoint
        tags_url = _ollama_tags_url(endpoint)
        if provider != "ollama":
            return {
                "ok": False,
                "provider": provider,
                "endpoint": tags_url,
                "models": [],
                "error": "provider is not ollama",
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
            profile_id = str(payload.get("profile_id") or "auto-rasp-json").strip() or "auto-rasp-json"
            return self.log_adapter.infer_mapping_profile(log, profile_id)

    def rasp_sample_log(self) -> dict:
        """Return the canonical RASP vendor-format sample used by the Dashboard
        日志自动适配 "加载示例" button. Sourced from samples_syslog/ so the UI
        example stays in sync with the raw vendor-format samples."""
        sample_path = Path(__file__).resolve().parent.parent / "samples_syslog" / "rasp" / "rasp_alert.json"
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
        product = explicit_product(payload)
        if product:
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

    def confirm_alert_false_positive(self, alert_id: str, body: dict) -> dict:
        with self.lock:
            linked = self.repo.get_linked_alert(alert_id)
            if not linked:
                raise ValueError("alert not found")
            analyst = str(body.get("analyst") or "soc-analyst")
            reason = str(body.get("reason") or "人工确认该告警符合业务场景下的误报模式")
            expires_at_ms = int(body["expires_at_ms"]) if body.get("expires_at_ms") else None
            outcome = self.memory.confirm_business_false_positive(linked, analyst, reason, expires_at_ms)
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

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json(200, {"ok": True, "stats": self.state.repo.stats()})
            return
        if parsed.path == "/api/config/llm":
            self._json(200, self.state.llm_config_payload())
            return
        if parsed.path == "/api/config/llm/models":
            self._json(200, self.state.list_ollama_models())
            return
        if parsed.path == "/api/mapping-profiles":
            self._json(200, {"profiles": self.state.list_mapping_profiles()})
            return
        if parsed.path == "/api/samples/rasp-alert":
            self._json(200, self.state.rasp_sample_log())
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
            limit = int(query.get("limit", ["50"])[0])
            self._json(200, {"cases": self.state.repo.list_cases(limit)})
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
        if parsed.path == "/api/config/llm":
            try:
                updated = self.state.update_llm_config(self._read_json())
                self._json(200, {"ok": True, "llm": updated})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path == "/api/mapping-profiles":
            try:
                saved = self.state.save_mapping_profile(self._read_json())
                self._json(200, {"ok": True, "profile": saved})
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path == "/api/mapping-profiles/dry-run":
            try:
                self._json(200, self.state.dry_run_mapping_profile(self._read_json()))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path == "/api/mapping-profiles/infer":
            try:
                self._json(200, self.state.infer_mapping_profile(self._read_json()))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path == "/api/memory/sweep":
            try:
                self._json(200, self.state.sweep_memory(self._read_json()))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path.startswith("/api/memory/") and parsed.path.endswith("/promote"):
            memory_id = parsed.path.split("/")[-2]
            try:
                self._json(200, self.state.promote_memory(memory_id, self._read_json()))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path.startswith("/api/memory/") and parsed.path.endswith("/reject"):
            memory_id = parsed.path.split("/")[-2]
            try:
                self._json(200, self.state.reject_memory(memory_id, self._read_json()))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path.startswith("/api/memory/") and parsed.path.endswith("/quarantine"):
            memory_id = parsed.path.split("/")[-2]
            try:
                self._json(200, self.state.quarantine_memory(memory_id, self._read_json()))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path.startswith("/api/alerts/") and parsed.path.endswith("/confirm-false-positive"):
            alert_id = unquote(parsed.path.split("/")[-2])
            try:
                self._json(200, self.state.confirm_alert_false_positive(alert_id, self._read_json()))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return
        if parsed.path != "/api/alerts":
            self._json(404, {"error": "not found"})
            return
        try:
            payload = self._read_json()
            profile_id = parse_qs(parsed.query).get("profile", [""])[0]
            alert = self.state.alert_from_payload(payload, profile_id)
            result = self.state.orchestrator.handle_alert(alert)
            self._json(202, result.to_dict())
        except Exception as exc:  # pragma: no cover - surfaced to local operator
            self._json(400, {"error": str(exc)})

    def _serve_static(self, path: str):
        static_dir = Path(__file__).parent / "static"
        if path in {"", "/"}:
            target = static_dir / "index.html"
        else:
            target = static_dir / path.lstrip("/")
        if not target.exists() or not target.is_file():
            self._json(404, {"error": "not found"})
            return
        content = target.read_bytes()
        mime = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, fmt: str, *args):
        print(f"[gateway] {self.address_string()} {fmt % args}")


def build_server(config: GatewayConfig) -> ThreadingHTTPServer:
    GatewayHandler.state = GatewayState(config)
    return ThreadingHTTPServer((config.server.host, config.server.port), GatewayHandler)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Defensive AI Gateway")
    parser.add_argument("--config", default="config/dev.yaml")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    server = build_server(config)
    print(f"Defensive AI Gateway listening on http://{config.server.host}:{config.server.port}")
    server.serve_forever()
