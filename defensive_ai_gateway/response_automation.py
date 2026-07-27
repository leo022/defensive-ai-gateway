from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from .json_safety import loads_bounded_json
from .models import NormalizedEvent, new_id
from .models import now_ms
from .network_safety import pinned_endpoint_handlers, resolve_http_endpoint_pin


ACTION_BLOCK_IP = "network.block_ip"
SUPPORTED_RESPONSE_ACTIONS = {ACTION_BLOCK_IP}
RESPONSE_EXECUTION_MODES = {"shadow", "manual", "auto"}
RESPONSE_TASK_STATUSES = {
    "waiting_configuration",
    "waiting_dispatch",
    "paused",
    "queued",
    "running",
    "retry_wait",
    "verified",
    "shadowed",
    "failed",
    "cancelled",
    "rollback_queued",
    "rollback_running",
    "rollback_retry",
    "rolled_back",
    "rollback_failed",
}

_BLOCK_TERMS = ("封禁", "阻断", "block", "deny")
_SOURCE_TERMS = ("来源", "源 ip", "源ip", "source ip", "src_ip", "恶意 ip", "恶意ip")
_NON_IP_ACTION_TERMS = (
    "rasp 策略",
    "rasp策略",
    "切换 rasp",
    "切换rasp",
    "隔离主机",
    "禁用账号",
)
_SECRET_ENV_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_TERMINAL_HTTP_CODES = {400, 401, 403, 404, 405, 409, 422}
_MAX_RESPONSE_BYTES = 65_536


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not allowed", headers, fp)


class ResponseExecutionError(RuntimeError):
    def __init__(self, message: str, *, retryable: bool, http_status: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.http_status = http_status


def _usable_ip(value: object) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        return ""
    return str(address)


def compile_response_action(
    action_text: str,
    event: NormalizedEvent | None,
    *,
    default_ttl_seconds: int = 1800,
) -> dict[str, Any]:
    """Compile one narrow action from a recommendation and immutable evidence."""
    text = " ".join(str(action_text or "").split())
    lowered = text.casefold()
    if not event or any(term in lowered for term in _NON_IP_ACTION_TERMS):
        return {}
    if not any(term in lowered for term in _BLOCK_TERMS):
        return {}
    if not any(term in lowered for term in _SOURCE_TERMS):
        return {}
    source_ip = _usable_ip(event.entities.get("src_ip"))
    if not source_ip:
        return {}
    raw_url = str(event.entities.get("url") or "").strip()
    parsed = urlsplit(raw_url) if raw_url else None
    host = str(event.entities.get("host") or (parsed.netloc if parsed else "") or "").strip()
    path = str((parsed.path if parsed else "") or "").strip()
    ttl = max(60, min(int(default_ttl_seconds), 86_400))
    prefix = 128 if ":" in source_ip else 32
    return {
        "action_type": ACTION_BLOCK_IP,
        "object": f"{source_ip}/{prefix}",
        "source_ip": source_ip,
        "scope": {
            "product": str(event.product or "").lower(),
            "host": host[:512],
            "path": path[:2048],
        },
        "duration_seconds": ttl,
        "reason": text[:1000],
        "event_id": event.event_id,
        "evidence_hash": hashlib.sha256(
            json.dumps(event.evidence, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "version": 1,
    }


def normalize_connector(payload: dict[str, Any], *, connector_id: str = "") -> dict[str, Any]:
    identifier = str(connector_id or payload.get("connector_id") or new_id("connector")).strip()
    name = " ".join(str(payload.get("name") or "").split())
    endpoint = str(payload.get("endpoint") or "").strip()
    mode = str(payload.get("execution_mode") or "shadow").strip().lower()
    secret_env = str(payload.get("secret_env") or "").strip()
    parsed = urlsplit(endpoint)
    if not identifier or len(identifier) > 128:
        raise ValueError("invalid connector id")
    if len(name) < 2 or len(name) > 100:
        raise ValueError("connector name must contain 2-100 characters")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("connector endpoint must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("connector endpoint must not contain credentials or fragments")
    host = parsed.hostname.lower().rstrip(".")
    loopback = host == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if parsed.scheme != "https" and not loopback:
        raise ValueError("remote response connector endpoints must use HTTPS")
    if mode not in RESPONSE_EXECUTION_MODES:
        raise ValueError("execution_mode must be shadow, manual or auto")
    if secret_env and not _SECRET_ENV_PATTERN.fullmatch(secret_env):
        raise ValueError("secret_env must be an uppercase environment variable name")
    return {
        "connector_id": identifier,
        "name": name,
        "connector_type": "generic_webhook",
        "endpoint": endpoint,
        "secret_env": secret_env,
        "execution_mode": mode,
        "enabled": bool(payload.get("enabled", False)),
        "max_ttl_seconds": max(
            60, min(int(payload.get("max_ttl_seconds", 3600)), 7 * 86_400)
        ),
        "timeout_seconds": max(1, min(int(payload.get("timeout_seconds", 10)), 60)),
    }


def normalize_response_policy(payload: dict[str, Any]) -> dict[str, Any]:
    maximum = max(60, min(int(payload.get("max_ttl_seconds", 86_400)), 7 * 86_400))
    default = max(60, min(int(payload.get("default_ttl_seconds", 1800)), maximum))
    raw_cidrs = payload.get("protected_cidrs") or []
    if isinstance(raw_cidrs, str):
        raw_cidrs = raw_cidrs.replace("\n", ",").split(",")
    if not isinstance(raw_cidrs, list):
        raise ValueError("protected_cidrs must be a list or comma-separated string")
    cidrs: list[str] = []
    for value in raw_cidrs:
        raw = str(value).strip()
        if not raw:
            continue
        try:
            rendered = str(ipaddress.ip_network(raw, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid protected CIDR: {raw}") from exc
        if rendered not in cidrs:
            cidrs.append(rendered)
    if len(cidrs) > 256:
        raise ValueError("at most 256 protected CIDRs are allowed")
    return {
        "enabled": bool(payload.get("enabled", False)),
        "default_ttl_seconds": default,
        "max_ttl_seconds": maximum,
        "protected_cidrs": cidrs,
    }


class ResponseAutomationService:
    def __init__(self, repo, *, allow_loopback_connectors: bool = False):  # noqa: ANN001
        self.repo = repo
        self.allow_loopback_connectors = bool(allow_loopback_connectors)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run,
            name="response-automation-dispatcher",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=3)

    def wake(self) -> None:
        self._wake.set()

    def policy(self) -> dict[str, Any]:
        return self.repo.get_response_policy()

    def connectors(self) -> list[dict[str, Any]]:
        return [self._public_connector(item) for item in self.repo.list_response_connectors()]

    @staticmethod
    def _public_connector(connector: dict[str, Any]) -> dict[str, Any]:
        payload = dict(connector)
        secret_env = str(payload.get("secret_env") or "")
        payload["credential_configured"] = bool(secret_env and os.getenv(secret_env))
        return payload

    def save_policy(self, payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
        policy = normalize_response_policy(payload)
        saved = self.repo.save_response_policy(policy, actor=actor)
        resumed = self.repo.resume_paused_response_tasks() if saved["enabled"] else 0
        self.repo.insert_audit(
            new_id("audit"),
            "response-policy",
            actor,
            "response_policy_updated",
            {
                "enabled": saved["enabled"],
                "default_ttl_seconds": saved["default_ttl_seconds"],
                "max_ttl_seconds": saved["max_ttl_seconds"],
                "protected_cidrs": saved["protected_cidrs"],
                "resumed_tasks": resumed,
            },
        )
        self.wake()
        return saved

    def save_connector(
        self, payload: dict[str, Any], *, actor: str, connector_id: str = ""
    ) -> dict[str, Any]:
        connector = normalize_connector(payload, connector_id=connector_id)
        host = (urlsplit(connector["endpoint"]).hostname or "").lower().rstrip(".")
        loopback = host == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if loopback and not self.allow_loopback_connectors:
            raise ValueError("loopback connector endpoints require explicit demo mode")
        if connector["enabled"]:
            conflicts = [
                item
                for item in self.repo.list_response_connectors(enabled_only=True)
                if item["connector_id"] != connector["connector_id"]
            ]
            if conflicts:
                raise ValueError("only one response connector can be enabled in this iteration")
        saved = self.repo.save_response_connector(connector, actor=actor)
        self.repo.insert_audit(
            new_id("audit"),
            saved["connector_id"],
            actor,
            "response_connector_saved",
            {
                "connector_id": saved["connector_id"],
                "name": saved["name"],
                "endpoint_host": host,
                "execution_mode": saved["execution_mode"],
                "enabled": saved["enabled"],
                "version": saved["version"],
            },
        )
        return self._public_connector(saved)

    def test_connector(self, connector_id: str, *, actor: str) -> dict[str, Any]:
        connector = self.repo.get_response_connector(connector_id)
        if not connector:
            raise KeyError("connector not found")
        error = ""
        try:
            response, status, _ = self._request(
                connector,
                "health_check",
                {"connector_id": connector_id},
                f"health:{connector_id}:{connector['version']}",
            )
            if not bool(response.get("ok")):
                raise ResponseExecutionError(
                    "connector health response did not confirm ok=true",
                    retryable=False,
                    http_status=status,
                )
            saved = self.repo.update_response_connector_health(connector_id, "healthy") or connector
        except Exception as exc:  # noqa: BLE001
            error = str(exc)[:1000]
            saved = self.repo.update_response_connector_health(
                connector_id, "error", error
            ) or connector
        self.repo.insert_audit(
            new_id("audit"),
            connector_id,
            actor,
            "response_connector_tested",
            {
                "connector_id": connector_id,
                "health_status": saved["health_status"],
                "error": error,
            },
        )
        return self._public_connector(saved)

    def create_for_approval(self, approval: dict[str, Any], *, actor: str) -> dict[str, Any] | None:
        action = dict(approval.get("action", {}).get("execution_action") or {})
        if str(action.get("action_type") or "") not in SUPPORTED_RESPONSE_ACTIONS:
            return None
        policy = self.policy()
        rejection_error = ""
        try:
            self._validate_action(action, policy)
        except (TypeError, ValueError) as exc:
            rejection_error = str(exc)
        connectors = self.repo.list_response_connectors(enabled_only=True)
        connector = connectors[0] if len(connectors) == 1 else None
        if connector:
            action["duration_seconds"] = min(
                int(action.get("duration_seconds") or policy["default_ttl_seconds"]),
                int(policy["max_ttl_seconds"]),
                int(connector["max_ttl_seconds"]),
            )
        if rejection_error:
            status = "failed"
        elif not connector:
            status = "waiting_configuration"
        elif not policy["enabled"]:
            status = "paused"
        elif connector["execution_mode"] == "shadow":
            status = "queued"
        elif connector["health_status"] != "healthy":
            status = "paused"
        elif connector["execution_mode"] == "manual":
            status = "waiting_dispatch"
        else:
            status = "queued"
        created = now_ms()
        digest_source = (
            f"{approval['approval_id']}\0{action['action_type']}\0"
            f"{action['object']}\0{action.get('version', 1)}"
        )
        idempotency_key = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()
        task, was_created = self.repo.create_response_task(
            {
                "task_id": f"response_{idempotency_key[:20]}",
                "approval_id": approval["approval_id"],
                "case_id": approval["case_id"],
                "event_id": approval["event_id"],
                "action_type": action["action_type"],
                "action": action,
                "connector_id": connector["connector_id"] if connector else None,
                "connector_version": int(connector["version"]) if connector else 0,
                "connector_snapshot": connector or {},
                "status": status,
                "idempotency_key": idempotency_key,
                "max_attempts": 5,
                "available_at_ms": created,
                "created_by": actor,
                "created_at_ms": created,
            },
            _commit=False,
        )
        if was_created:
            self.repo.insert_audit(
                new_id("audit"),
                approval["case_id"],
                actor,
                "response_task_created",
                {
                    "case_id": approval["case_id"],
                    "approval_id": approval["approval_id"],
                    "task_id": task["task_id"],
                    "action_type": action["action_type"],
                    "object": action["object"],
                    "status": status,
                    "connector_id": task.get("connector_id") or "",
                },
                _commit=False,
            )
        if rejection_error:
            task = self.repo.finish_response_task(
                task["task_id"], "failed", error=rejection_error, _commit=False
            ) or task
        return task

    @staticmethod
    def _validate_action(action: dict[str, Any], policy: dict[str, Any]) -> None:
        address = ipaddress.ip_address(str(action.get("source_ip") or ""))
        if int(action.get("duration_seconds") or 0) < 60:
            raise ValueError("response duration must be at least 60 seconds")
        if int(action.get("duration_seconds") or 0) > int(policy["max_ttl_seconds"]):
            raise ValueError("response duration exceeds the global maximum")
        for cidr in policy.get("protected_cidrs", []):
            if address in ipaddress.ip_network(cidr, strict=False):
                raise ValueError(f"response object {address} is protected by {cidr}")

    def dispatch(self, task_id: str, *, actor: str) -> dict[str, Any]:
        task = self.repo.get_response_task(task_id)
        if not task:
            raise KeyError("response task not found")
        policy = self.policy()
        if not policy["enabled"]:
            raise ValueError("response automation is disabled")
        preflight = self.repo.response_task_preflight(task_id)
        if not preflight or not preflight["eligible"]:
            raise ValueError("response task approval is stale or its Case is terminal")
        if not task.get("connector_snapshot"):
            connectors = self.repo.list_response_connectors(enabled_only=True)
            if len(connectors) != 1:
                raise ValueError("configure exactly one enabled response connector before dispatch")
            candidate = connectors[0]
            if (
                candidate["execution_mode"] != "shadow"
                and candidate["health_status"] != "healthy"
            ):
                raise ValueError("response connector must pass its health test before binding")
            task = self.repo.bind_response_task_connector(task_id, candidate)
            if not task:
                raise ValueError("response task is not eligible for connector binding")
            self.repo.insert_audit(
                new_id("audit"),
                task["case_id"],
                actor,
                "response_connector_bound",
                {
                    "case_id": task["case_id"],
                    "task_id": task_id,
                    "connector_id": candidate["connector_id"],
                    "connector_version": candidate["version"],
                },
            )
        self._validate_action(task["action"], policy)
        connector = self._runtime_connector(task)
        if connector["execution_mode"] != "shadow" and connector["health_status"] != "healthy":
            raise ValueError("response connector must pass its health test before dispatch")
        queued = self.repo.queue_response_task(task_id)
        if not queued:
            raise ValueError("response task is not eligible for dispatch")
        self.repo.insert_audit(
            new_id("audit"), task["case_id"], actor, "response_task_queued",
            {"case_id": task["case_id"], "task_id": task_id},
        )
        self.wake()
        return queued

    def rollback(self, task_id: str, *, actor: str) -> dict[str, Any]:
        task = self.repo.get_response_task(task_id)
        if not task:
            raise KeyError("response task not found")
        queued = self.repo.queue_response_task(task_id, rollback=True)
        if not queued:
            raise ValueError("response task is not eligible for rollback")
        self.repo.insert_audit(
            new_id("audit"), task["case_id"], actor, "response_rollback_queued",
            {"case_id": task["case_id"], "task_id": task_id},
        )
        self.wake()
        return queued

    def _runtime_connector(self, task: dict[str, Any]) -> dict[str, Any]:
        snapshot = dict(task.get("connector_snapshot") or {})
        current = self.repo.get_response_connector(str(task.get("connector_id") or ""))
        if current and int(current["version"]) == int(task.get("connector_version") or 0):
            snapshot["health_status"] = current["health_status"]
        return snapshot

    def _run(self) -> None:
        last_maintenance = 0.0
        while not self._stop.is_set():
            current = time.monotonic()
            if current - last_maintenance >= 2.0:
                self.repo.queue_expired_response_tasks()
                self.repo.recover_stale_response_tasks(now_ms() - 120_000)
                last_maintenance = current
            task = self.repo.claim_response_task()
            if not task:
                self._wake.wait(0.5)
                self._wake.clear()
                continue
            try:
                self._execute_task(task)
            except Exception as exc:  # noqa: BLE001
                self._record_failure(task, exc)

    def _execute_task(self, task: dict[str, Any]) -> None:
        rollback = task["status"] == "rollback_running"
        connector = self._runtime_connector(task)
        if not connector:
            raise ResponseExecutionError(
                "approved connector snapshot is unavailable", retryable=False
            )
        if not rollback:
            preflight = self.repo.response_task_preflight(task["task_id"])
            if not preflight or not preflight["eligible"]:
                raise ResponseExecutionError(
                    "response task approval is stale or its Case is terminal",
                    retryable=False,
                )
            policy = self.policy()
            if not policy["enabled"]:
                self.repo.finish_response_task(
                    task["task_id"], "paused", error="response policy is disabled"
                )
                return
            try:
                self._validate_action(task["action"], policy)
            except ValueError as exc:
                raise ResponseExecutionError(str(exc), retryable=False) from exc
            if connector["execution_mode"] != "shadow" and connector["health_status"] != "healthy":
                raise ResponseExecutionError(
                    "response connector is not healthy", retryable=True
                )
        if connector["execution_mode"] == "shadow":
            final = "rolled_back" if rollback else "shadowed"
            self.repo.finish_response_task(task["task_id"], final)
            self.repo.insert_audit(
                new_id("audit"), task["case_id"], "response-dispatcher",
                "response_task_shadowed" if not rollback else "response_rollback_completed",
                {"case_id": task["case_id"], "task_id": task["task_id"], "status": final},
            )
            return
        operation = "rollback" if rollback else "apply"
        response, http_status, request_hash = self._request(
            connector,
            operation,
            task["action"],
            task["idempotency_key"],
            remote_rule_id=str(task.get("remote_rule_id") or ""),
        )
        if not bool(response.get("ok")):
            raise ResponseExecutionError(
                "connector response did not confirm ok=true",
                retryable=False,
                http_status=http_status,
            )
        remote_rule_id = str(response.get("rule_id") or task.get("remote_rule_id") or "")[:512]
        if not rollback and not remote_rule_id:
            raise ResponseExecutionError(
                "connector apply response omitted rule_id",
                retryable=False,
                http_status=http_status,
            )
        self.repo.insert_response_attempt(
            {
                "attempt_id": new_id("attempt"),
                "task_id": task["task_id"],
                "operation": operation,
                "attempt_no": task["attempts"],
                "request_hash": request_hash,
                "http_status": http_status,
                "outcome": "rolled_back" if rollback else "applied",
                "response_excerpt": json.dumps(response, ensure_ascii=False, sort_keys=True),
            }
        )
        if rollback:
            final = "rolled_back"
        else:
            self.repo.record_response_rule_id(task["task_id"], remote_rule_id)
            task["remote_rule_id"] = remote_rule_id
            verify, verify_status, verify_hash = self._request(
                connector,
                "verify",
                task["action"],
                task["idempotency_key"],
                remote_rule_id=remote_rule_id,
            )
            verified = bool(verify.get("ok")) and str(verify.get("status") or "").lower() in {
                "active", "applied", "verified", "blocked"
            }
            self.repo.insert_response_attempt(
                {
                    "attempt_id": new_id("attempt"),
                    "task_id": task["task_id"],
                    "operation": "verify",
                    "attempt_no": task["attempts"],
                    "request_hash": verify_hash,
                    "http_status": verify_status,
                    "outcome": "verified" if verified else "verification_failed",
                    "response_excerpt": json.dumps(verify, ensure_ascii=False, sort_keys=True),
                }
            )
            if not verified:
                raise ResponseExecutionError(
                    "connector verification did not confirm an active rule",
                    retryable=True,
                    http_status=verify_status,
                )
            final = "verified"
        result = self.repo.finish_response_task(
            task["task_id"], final, remote_rule_id=remote_rule_id
        )
        self.repo.insert_audit(
            new_id("audit"),
            task["case_id"],
            "response-dispatcher",
            "response_rollback_completed" if rollback else "response_task_verified",
            {
                "case_id": task["case_id"],
                "task_id": task["task_id"],
                "remote_rule_id": remote_rule_id,
                "status": result["status"] if result else final,
            },
        )

    def _record_failure(self, task: dict[str, Any], exc: Exception) -> None:
        retryable = bool(getattr(exc, "retryable", True))
        attempts = int(task.get("attempts") or 1)
        max_attempts = int(task.get("max_attempts") or 5)
        rollback = task.get("status") == "rollback_running"
        if retryable and attempts < max_attempts:
            status = "rollback_retry" if rollback else "retry_wait"
            delay_ms = min(300_000, 1000 * (2 ** min(attempts - 1, 8)))
        else:
            status = "rollback_failed" if rollback else "failed"
            delay_ms = 0
        self.repo.insert_response_attempt(
            {
                "attempt_id": new_id("attempt"),
                "task_id": task["task_id"],
                "operation": (
                    "rollback" if rollback else "verify" if task.get("remote_rule_id") else "apply"
                ),
                "attempt_no": attempts,
                "http_status": getattr(exc, "http_status", None),
                "outcome": status,
                "error": str(exc),
            }
        )
        self.repo.finish_response_task(
            task["task_id"], status, error=str(exc), retry_delay_ms=delay_ms
        )
        self.repo.insert_audit(
            new_id("audit"),
            task["case_id"],
            "response-dispatcher",
            "response_task_failed",
            {
                "case_id": task["case_id"],
                "task_id": task["task_id"],
                "status": status,
                "error_type": type(exc).__name__,
                "retryable": retryable,
            },
        )

    def _request(
        self,
        connector: dict[str, Any],
        operation: str,
        action: dict[str, Any],
        idempotency_key: str,
        *,
        remote_rule_id: str = "",
    ) -> tuple[dict[str, Any], int, str]:
        endpoint = str(connector["endpoint"])
        try:
            pin = resolve_http_endpoint_pin(
                endpoint,
                backend="response connector",
                require_https_for_remote=True,
            )
        except ValueError as exc:
            raise ResponseExecutionError(str(exc), retryable=False) from exc
        host = (urlsplit(endpoint).hostname or "").lower().rstrip(".")
        loopback = host == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if loopback and not self.allow_loopback_connectors:
            raise ResponseExecutionError(
                "loopback response connector is disabled", retryable=False
            )
        payload = {
            "operation": operation,
            "task_idempotency_key": idempotency_key,
            "remote_rule_id": remote_rule_id,
            "action": action,
        }
        operation_idempotency_key = hashlib.sha256(
            f"{idempotency_key}\0{operation}".encode("utf-8")
        ).hexdigest()
        payload["idempotency_key"] = operation_idempotency_key
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        request_hash = hashlib.sha256(body).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Idempotency-Key": operation_idempotency_key,
            "User-Agent": "defensive-ai-response-orchestrator/1.0",
        }
        secret_env = str(connector.get("secret_env") or "")
        if secret_env:
            token = str(os.getenv(secret_env) or "")
            if not token:
                raise ResponseExecutionError(
                    f"connector credential environment variable {secret_env} is not set",
                    retryable=False,
                )
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        opener = urllib.request.build_opener(
            _NoRedirectHandler(), *pinned_endpoint_handlers(pin)
        )
        try:
            with opener.open(request, timeout=float(connector["timeout_seconds"])) as response:
                status = int(response.status)
                declared = response.headers.get("Content-Length")
                if declared and int(declared) > _MAX_RESPONSE_BYTES:
                    raise ResponseExecutionError(
                        "connector response is too large", retryable=False, http_status=status
                    )
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise ResponseExecutionError(
                        "connector response is too large", retryable=False, http_status=status
                    )
        except urllib.error.HTTPError as exc:
            retryable = exc.code not in _TERMINAL_HTTP_CODES and (
                exc.code == 429 or exc.code >= 500
            )
            raise ResponseExecutionError(
                f"connector returned HTTP {exc.code}",
                retryable=retryable,
                http_status=exc.code,
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ResponseExecutionError(
                f"connector request failed: {exc}", retryable=True
            ) from exc
        try:
            decoded = loads_bounded_json(raw.decode("utf-8"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ResponseExecutionError(
                "connector returned invalid JSON", retryable=False, http_status=status
            ) from exc
        if not isinstance(decoded, dict):
            raise ResponseExecutionError(
                "connector response must be a JSON object",
                retryable=False,
                http_status=status,
            )
        return decoded, status, request_hash
