from __future__ import annotations

import copy
import json
import re
from typing import Any

from .config import PolicyConfig


SECRET_PATTERNS = [
    re.compile(r"(?i)\b((?:bearer|basic)\s+)[a-z0-9+/=._~\-]+"),
    re.compile(
        r"(?i)([\"']?(?:api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|"
        r"id[_-]?token|client[_-]?secret|password|passwd)[\"']?\s*[:=]\s*[\"']?)"
        r"[^\"'\s,;}&]+"
    ),
    # Avoid treating a long decimal tail such as 0.9199999999999999 as an ID.
    re.compile(r"(?<![\d.])(?:\d{15}|\d{17}[0-9Xx])(?![\d.])"),
]

_BUILTIN_SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "x_api_key",
    "client_secret",
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "session",
}

_OMIT = object()


# Evidence arrives in source order. RASP sources commonly put a long stack trace
# before hook_data and request context, so a generic list truncation can consume
# the whole model budget before the decisive fields are reached. Keep the model
# projection ordered by analytical value instead. The immutable original alert
# is retained separately; this only shapes the bounded LLM-facing copy.
_EVIDENCE_CONTEXT_PRIORITY = {
    "request_context": 0,
    "hook_data": 0,
    "hook_data_summary": 0,
    "rasp_items_context": 0,
    "request_parameters": 1,
    "sink": 1,
    "taint_source": 1,
    "payload_category": 1,
    "rule_id": 2,
    "rule_name": 2,
    "action": 2,
    "method": 2,
    "url": 2,
    "uri": 2,
    "src_ip": 2,
    "host": 2,
    "status": 2,
    "exception": 3,
    "stack_trace": 4,
    "stacktrace": 4,
    "rasp_evidence_integrity": 2,
}

_EVIDENCE_CONTEXT_ITEM_CAPS = {
    "request_context": 700,
    "hook_data": 700,
    "hook_data_summary": 700,
    "rasp_items_context": 1500,
    "request_parameters": 450,
    "sink": 500,
    "taint_source": 500,
    "payload_category": 500,
    "rule_id": 350,
    "rule_name": 350,
    "action": 300,
    "method": 200,
    "url": 450,
    "uri": 450,
    "src_ip": 200,
    "host": 300,
    "status": 200,
    "exception": 500,
    "stack_trace": 1000,
    "stacktrace": 1000,
    "rasp_evidence_integrity": 450,
}
_DEFAULT_EVIDENCE_CONTEXT_ITEM_CAP = 320


def _canonical_field_name(value: Any) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value).strip())
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8"))


def _fit_json_value(value: Any, budget: int, *, top_level: bool = False) -> Any:
    """Return a structurally valid JSON value whose encoding fits ``budget``."""
    if budget < 2:
        return _OMIT
    try:
        if _json_size(value) <= budget:
            return copy.deepcopy(value)
    except (TypeError, ValueError):
        return _OMIT

    if isinstance(value, str):
        marker = "...[TRUNCATED]"
        if _json_size(marker) > budget:
            marker = ""
        low, high = 0, len(value)
        best = marker
        while low <= high:
            mid = (low + high) // 2
            candidate = value[:mid] + marker
            if _json_size(candidate) <= budget:
                best = candidate
                low = mid + 1
            else:
                high = mid - 1
        return best if _json_size(best) <= budget else _OMIT

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        priority = {
            "result_contract_version": 0,
            "product": 1,
            "severity": 2,
            "event_type": 3,
            "entities": 4,
            "evidence": 5,
            "memory": 6,
            "focus": 7,
            "report_outline": 8,
        }
        keys = sorted(
            value,
            key=lambda key: (priority.get(str(key), 100) if top_level else 0, str(key)),
        )
        for original_key in keys:
            key = str(original_key)
            with_null = dict(result)
            with_null[key] = None
            available = budget - (_json_size(with_null) - _json_size(None))
            fitted = _fit_json_value(value[original_key], available)
            if fitted is _OMIT:
                continue
            candidate = dict(result)
            candidate[key] = fitted
            if _json_size(candidate) <= budget:
                result = candidate
        return result if _json_size(result) <= budget else _OMIT

    if isinstance(value, list):
        result: list[Any] = []
        for item in value:
            with_null = [*result, None]
            available = budget - (_json_size(with_null) - _json_size(None))
            fitted = _fit_json_value(item, available)
            if fitted is _OMIT:
                break
            candidate = [*result, fitted]
            if _json_size(candidate) > budget:
                break
            result = candidate
        return result if _json_size(result) <= budget else _OMIT

    return _OMIT


def _evidence_type(item: Any) -> str:
    if not isinstance(item, dict):
        return "evidence"
    return str(item.get("type") or "evidence").strip().lower()


def _compact_evidence_item(item: Any) -> dict[str, Any]:
    """Keep the model contract fields while discarding storage-only metadata."""
    if not isinstance(item, dict):
        return {"type": "evidence", "value": item}
    compact: dict[str, Any] = {"type": str(item.get("type") or "evidence")}
    if "value" in item:
        compact["value"] = item.get("value")
    why = item.get("why_it_matters")
    if why not in (None, ""):
        compact["why_it_matters"] = why
    return compact


def _fit_evidence_context(evidence: list[Any], budget: int) -> list[dict[str, Any]]:
    """Fit evidence without allowing an early bulky item to hide later context."""
    if budget < 2:
        return []
    ranked = sorted(
        enumerate(evidence),
        key=lambda pair: (_EVIDENCE_CONTEXT_PRIORITY.get(_evidence_type(pair[1]), 3), pair[0]),
    )
    result: list[dict[str, Any]] = []
    for _index, original_item in ranked:
        item_type = _evidence_type(original_item)
        compact = _compact_evidence_item(original_item)
        # Work out the exact room for an additional array element. This avoids
        # relying on a best-effort share after an earlier stack trace is trimmed.
        with_null = [*result, None]
        available = budget - (_json_size(with_null) - _json_size(None))
        if available < 2:
            break
        cap = _EVIDENCE_CONTEXT_ITEM_CAPS.get(item_type, _DEFAULT_EVIDENCE_CONTEXT_ITEM_CAP)
        fitted = _fit_json_value(compact, min(available, cap))
        if not isinstance(fitted, dict):
            continue
        # A meaningful item must retain its type. Do not add a value-only or
        # empty fragment simply because it happens to fit in the final bytes.
        if not str(fitted.get("type") or "").strip():
            continue
        candidate = [*result, fitted]
        if _json_size(candidate) <= budget:
            result = candidate
    return result


class PolicyEngine:
    def __init__(self, config: PolicyConfig):
        self.config = config

    def redact(self, value: Any) -> Any:
        cloned = copy.deepcopy(value)
        return self._redact_any(cloned)

    def _redact_any(self, value: Any) -> Any:
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            configured = {_canonical_field_name(field) for field in self.config.redact_fields}
            for key, item in value.items():
                field = _canonical_field_name(key)
                if field in configured or field in _BUILTIN_SENSITIVE_FIELDS:
                    redacted[key] = "[REDACTED]"
                else:
                    redacted[key] = self._redact_any(item)
            return redacted
        if isinstance(value, list):
            return [self._redact_any(item) for item in value]
        if isinstance(value, str):
            text = value
            for pattern in SECRET_PATTERNS:
                text = pattern.sub(lambda m: f"{m.group(1) if m.groups() else ''}[REDACTED]", text)
            return text
        return value

    def action_mode(self, action: str) -> str:
        if self.config.mode == "read_only":
            return "approve_required" if self.requires_approval(action) else "observe"
        if self.requires_approval(action):
            return "approve_required"
        return "automated_read_only"

    def requires_approval(self, action: str) -> bool:
        lowered = action.lower()
        approval_terms = {word.lower() for word in self.config.require_approval_for}
        approval_terms.update(
            {
                "block",
                "isolate",
                "change",
                "disable",
                "penetration",
                "exploit",
                "payload",
                "scan",
                "封禁",
                "隔离",
                "阻断",
                "变更",
                "关闭",
                "禁用",
                "模拟攻击",
                "攻击模拟",
                "注入测试",
                "渗透",
                "扫描",
                "压力",
            }
        )
        return any(term and term in lowered for term in approval_terms)

    def safe_action_text(self, action: str) -> str:
        text = action.strip()
        if not text:
            return text
        if self.requires_approval(text):
            return f"{text}（仅限授权测试环境或审批后执行，不得直接在生产执行）"
        return text

    def truncate_prompt_payload(self, payload: dict[str, Any]) -> str:
        text = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        if len(text) <= self.config.max_prompt_chars:
            return text
        return text[: self.config.max_prompt_chars] + "...[TRUNCATED]"

    def sanitize_context(self, context: dict[str, Any]) -> dict[str, Any]:
        """Redact + bound the size of any payload sent to an LLM.

        Single choke point for the model-bound context channel: deep-redacts
        sensitive fields/patterns (so secrets never leave the process even when
        the prompt is built from a different path) and drops list-valued
        evidence/memory tails when the serialized form exceeds
        ``max_context_bytes``. Structured trimming — rather than slicing the JSON
        string — avoids producing unparseable or mid-UTF8 payloads for the model.
        """
        redacted = self.redact(context)
        if not isinstance(redacted, dict):
            return redacted
        # ``{}`` is the smallest JSON object, so two bytes is the effective lower
        # bound. Give large channels independent shares first so one evidence list
        # cannot crowd entities and governed memory out of the model context.
        max_bytes = max(2, int(getattr(self.config, "max_context_bytes", 20000)))
        shares = {
            "result_contract_version": 0.08,
            "product": 0.06,
            "severity": 0.06,
            "event_type": 0.12,
            "entities": 0.18,
            "evidence": 0.28,
            "memory": 0.25,
            "focus": 0.10,
            "report_outline": 0.10,
        }
        # For RASP, the evidence itself is the primary source of truth. Preserve
        # enough room for request context, hook data, every item summary and the
        # dangerous call path before allocating optional long-term memory.
        if str(redacted.get("product") or "").strip().lower() == "rasp":
            shares["evidence"] = 0.50
            shares["memory"] = 0.15

        evidence = redacted.get("evidence")
        if isinstance(evidence, list):
            redacted["evidence"] = _fit_evidence_context(
                evidence,
                max(2, int(max_bytes * shares["evidence"])),
            )
        for key, share in shares.items():
            if key == "evidence":
                continue
            if key not in redacted:
                continue
            fitted = _fit_json_value(redacted[key], max(2, int(max_bytes * share)))
            if fitted is _OMIT:
                redacted.pop(key, None)
            else:
                redacted[key] = fitted

        fitted_context = _fit_json_value(redacted, max_bytes, top_level=True)
        if not isinstance(fitted_context, dict):
            return {}
        # Future edits must not turn the bound into a best-effort hint.
        if _json_size(fitted_context) > max_bytes:  # pragma: no cover
            return {}
        return fitted_context
