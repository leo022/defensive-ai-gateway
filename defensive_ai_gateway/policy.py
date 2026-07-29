from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping
from typing import Any

from .config import PolicyConfig


_QUOTED_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>[\"']?(?:api[_-]?key|x-api-key|access[_-]?token|"
    r"refresh[_-]?token|id[_-]?token|token|client[_-]?secret|secret|credential|"
    r"password|passwd|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|"
    r"session(?:[_-]?id)?|jsessionid|customer[_-]?id|email|phone|mobile|"
    r"account[_-]?number|card[_-]?number|bank[_-]?card)[\"']?\s*[:=]\s*)"
    r"(?P<quote>[\"'])(?:\\.|(?!(?P=quote)).)*(?P=quote)"
)


SECRET_PATTERNS = [
    re.compile(r"(?i)(\bhttps?://)[^/@\s:]+:[^/@\s]+(?=@)"),
    re.compile(r"(?i)(\b(?:cookie|set-cookie)\s*[:=]\s*[\"']?)[^\"'\r\n]+"),
    re.compile(r"(?i)\b((?:bearer|basic)\s+)[a-z0-9+/=._~\-]+"),
    re.compile(
        r"(?i)([\"']?(?:api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|"
        r"id[_-]?token|token|client[_-]?secret|secret|credential|password|passwd|authorization|proxy[_-]?authorization|"
        r"cookie|set[_-]?cookie|session(?:[_-]?id)?|jsessionid|customer[_-]?id|email|phone|mobile|"
        r"account[_-]?number|card[_-]?number|bank[_-]?card)[\"']?\s*[:=]\s*[\"']?)"
        r"[^\"'\s,;}&]+"
    ),
    re.compile(r"(?i)(?<![a-z0-9._%+\-])[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}(?![a-z0-9.\-])"),
    re.compile(r"(?<!\d)(?:\+?86[\s-]?)?1[3-9]\d{9}(?!\d)"),
    # Avoid treating a long decimal tail such as 0.9199999999999999 as an ID.
    re.compile(r"(?<![\d.])(?:\d{15}|\d{17}[0-9Xx])(?![\d.])"),
]

_BUILTIN_SENSITIVE_FIELDS = {
    "account_number",
    "bank_card",
    "card_number",
    "credential",
    "credentials",
    "customer_id",
    "email",
    "id_card",
    "identity_card",
    "mobile",
    "password",
    "passwd",
    "phone",
    "secret",
    "ssn",
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
    "session_id",
}

_SENSITIVE_FIELD_MARKERS = frozenset(
    {
        "account",
        "authorization",
        "card",
        "cookie",
        "credential",
        "credentials",
        "customer",
        "email",
        "identity",
        "mobile",
        "passwd",
        "password",
        "phone",
        "secret",
        "session",
        "ssn",
        "token",
    }
)
_SENSITIVE_FIELD_QUALIFIERS = frozenset(
    {
        "card",
        "credential",
        "credentials",
        "email",
        "hash",
        "header",
        "id",
        "identifier",
        "key",
        "mobile",
        "number",
        "phone",
        "secret",
        "sha256",
        "token",
        "value",
    }
)

_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
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
    "stack_trace": 1,
    "stacktrace": 1,
    "rasp_evidence_integrity": 2,
}

_EVIDENCE_CONTEXT_ITEM_CAPS = {
    "request_context": 3000,
    "hook_data": 1800,
    "hook_data_summary": 1800,
    "rasp_items_context": 5000,
    "request_parameters": 1800,
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


def _is_sensitive_derived_field(
    field: str,
    configured_fields: set[str] | None = None,
) -> bool:
    if not (
        field.endswith("_hash")
        or field.endswith("_sha256")
        or field in {"hash", "sha256"}
    ):
        return False
    sensitive_fields = set(_BUILTIN_SENSITIVE_FIELDS)
    sensitive_fields.update(configured_fields or set())
    return any(
        field == sensitive
        or field.startswith(f"{sensitive}_")
        or field.endswith(f"_{sensitive}")
        or f"_{sensitive}_" in field
        for sensitive in sensitive_fields
    )


def is_sensitive_field_name(
    value: Any,
    configured_fields: set[str] | None = None,
) -> bool:
    """Classify secret/identifier fields without treating metric prefixes as IDs."""
    field = _canonical_field_name(value)
    configured = {
        _canonical_field_name(item) for item in configured_fields or set()
    }
    if (
        field in configured
        or field in _BUILTIN_SENSITIVE_FIELDS
        or _is_sensitive_derived_field(field, configured)
    ):
        return True
    parts = field.split("_") if field else []
    if (
        len(parts) > 1
        and parts[-1] in _SENSITIVE_FIELD_QUALIFIERS
        and any(marker in parts[:-1] for marker in _SENSITIVE_FIELD_MARKERS)
    ):
        return True
    for marker in _SENSITIVE_FIELD_MARKERS:
        if field.endswith(f"_{marker}"):
            return True
        prefix = f"{marker}_"
        if not field.startswith(prefix):
            continue
        remainder = field[len(prefix) :]
        if remainder.split("_")[-1] in _SENSITIVE_FIELD_QUALIFIERS:
            return True
    return False


def _is_digest_field(field: str) -> bool:
    return field in {"hash", "sha256"} or field.endswith(("_hash", "_sha256"))


def _redact_sensitive_text(value: str) -> str:
    text = _QUOTED_SENSITIVE_ASSIGNMENT.sub(
        lambda match: (
            f"{match.group('prefix')}{match.group('quote')}"
            f"[REDACTED]{match.group('quote')}"
        ),
        value,
    )
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(
            lambda match: (
                f"{match.group(1) if match.groups() else ''}[REDACTED]"
            ),
            text,
        )
    return text


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
            "active_raw_observation": 0,
            "scope": 1,
            "execution_boundary": 2,
            "investigation_notes": 3,
            "observations": 4,
            "result_contract_version": 5,
            "product": 6,
            "severity": 7,
            "event_type": 8,
            "entities": 9,
            "evidence": 10,
            "memory": 11,
            "focus": 12,
            "report_outline": 13,
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

    def redact(
        self,
        value: Any,
        *,
        trusted_digest_paths: Mapping[tuple[str | int, ...], str] | None = None,
    ) -> Any:
        """Redact a value, preserving only caller-attested digest path/value pairs.

        A trusted digest must be an exact SHA-256 value at an explicit hash field
        path. Callers are responsible for supplying only controller-owned,
        immutable digests. Entries below sensitive keys are ignored.
        """
        cloned = copy.deepcopy(value)
        trusted = self._validated_trusted_digest_paths(trusted_digest_paths)
        return self._redact_any(cloned, (), trusted)

    def _validated_trusted_digest_paths(
        self,
        trusted_digest_paths: Mapping[tuple[str | int, ...], str] | None,
    ) -> dict[tuple[str | int, ...], str]:
        if not trusted_digest_paths:
            return {}
        configured = {
            _canonical_field_name(field) for field in self.config.redact_fields
        }
        trusted: dict[tuple[str | int, ...], str] = {}
        for raw_path, digest in trusted_digest_paths.items():
            path = tuple(raw_path)
            if (
                not path
                or not isinstance(digest, str)
                or _SHA256_HEX.fullmatch(digest) is None
                or not isinstance(path[-1], str)
            ):
                continue
            leaf = _canonical_field_name(path[-1])
            if not _is_digest_field(leaf):
                continue
            sensitive_path = False
            for segment in path:
                if not isinstance(segment, str):
                    continue
                field = _canonical_field_name(segment)
                if is_sensitive_field_name(field, configured) or any(
                    pattern.search(segment) for pattern in SECRET_PATTERNS
                ):
                    sensitive_path = True
                    break
            if not sensitive_path:
                trusted[path] = digest
        return trusted

    def _redact_any(
        self,
        value: Any,
        path: tuple[str | int, ...],
        trusted_digest_paths: Mapping[tuple[str | int, ...], str],
    ) -> Any:
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            configured = {_canonical_field_name(field) for field in self.config.redact_fields}
            for key, item in value.items():
                field = _canonical_field_name(key)
                item_path = (*path, key)
                redacted_key = (
                    _redact_sensitive_text(key) if isinstance(key, str) else key
                )
                if redacted_key in redacted and redacted_key != key:
                    base_key = str(redacted_key)
                    suffix = 2
                    while f"{base_key}_{suffix}" in redacted:
                        suffix += 1
                    redacted_key = f"{base_key}_{suffix}"
                if is_sensitive_field_name(field, configured):
                    redacted[redacted_key] = "[REDACTED]"
                else:
                    redacted[redacted_key] = self._redact_any(
                        item,
                        item_path,
                        trusted_digest_paths,
                    )
            return redacted
        if isinstance(value, list):
            return [
                self._redact_any(item, (*path, index), trusted_digest_paths)
                for index, item in enumerate(value)
            ]
        if isinstance(value, str):
            if trusted_digest_paths.get(path) == value:
                return value
            return _redact_sensitive_text(value)
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
        # Preserve valid JSON at the final prompt boundary. The context has
        # already been byte-bounded, but max_prompt_chars may be lower and a raw
        # string slice would leave the model with malformed evidence.
        fitted = _fit_json_value(
            payload,
            max(2, int(self.config.max_prompt_chars)),
            top_level=True,
        )
        if not isinstance(fitted, dict):
            return "{}"
        return json.dumps(fitted, ensure_ascii=False, sort_keys=True)

    def sanitize_json_value(
        self,
        value: Any,
        max_bytes: int,
        *,
        trusted_digest_paths: Mapping[tuple[str | int, ...], str] | None = None,
    ) -> Any:
        """Redact and structurally fit a tool/report value to an exact byte cap."""
        budget = max(2, int(max_bytes))
        redacted = self.redact(
            value,
            trusted_digest_paths=trusted_digest_paths,
        )
        fitted = _fit_json_value(redacted, budget, top_level=isinstance(redacted, dict))
        if fitted is _OMIT:
            return {} if isinstance(redacted, dict) else []
        if _json_size(fitted) > budget:  # pragma: no cover
            return {} if isinstance(redacted, dict) else []
        return fitted

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
