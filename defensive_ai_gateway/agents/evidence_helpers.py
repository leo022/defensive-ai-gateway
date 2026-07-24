"""Shared text-shaping helpers for evidence/dimension synthesis.

Both ``SecurityAgent`` (agents/base.py) and ``LocalHeuristicLLM`` (llm.py) build
analyst-readable evidence strings from normalized events. Previously each
duplicated ``_short``/``_fact``/``_join_facts`` with subtly different truncation
lengths (100 vs 120 chars), which drifted over time. These module-level helpers
are the single source of truth so the heuristic analyzer and the agent's
synthesizer can never diverge again.
"""
from __future__ import annotations

import json
from typing import Any

SHORT_LIMIT = 100


def short_text(value: Any, limit: int = SHORT_LIMIT) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    text = text.replace("\n", " ").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def fact(label: str, value: Any, limit: int = SHORT_LIMIT) -> str:
    if value in ("", None, [], {}):
        return ""
    return f"{label}={short_text(value, limit)}"


def request_parameters_fact(value: Any, label: str = "请求参数") -> str:
    """Render RASP parameter state without exposing the original request payload."""
    if value in ("", None):
        return ""
    if isinstance(value, dict):
        state = str(value.get("state") or "").strip().lower()
        value_format = str(value.get("format") or "").strip()
        format_label = {
            "json_object": "JSON 对象",
            "json_array": "JSON 数组",
            "text": "文本",
        }.get(value_format, value_format)
        if state == "empty":
            return f"{label}=空 {format_label or '对象'}（上游未提供有效参数）"
        if state == "present":
            count = value.get("field_count", value.get("item_count"))
            detail = format_label or "结构化参数"
            if isinstance(count, int):
                detail += f"，数量 {count}"
            elif isinstance(value.get("length"), int):
                detail += f"，长度 {value['length']}"
            return f"{label}=已提供（{detail}）"
        return f"{label}=已提供（对象，字段数 {len(value)}）"
    if isinstance(value, list):
        return f"{label}=已提供（数组，数量 {len(value)}）"
    if isinstance(value, str):
        text = value.strip()
        if text in {"{}", "[]"}:
            return f"{label}=空 JSON（上游未提供有效参数）"
        return f"{label}=已提供（文本长度 {len(text)}）"
    return f"{label}=已提供"


def request_context_fact(value: Any, label: str = "请求上下文") -> str:
    """Describe RASP request/body availability without exposing the raw payload."""
    if value in ("", None):
        return ""
    if not isinstance(value, dict):
        return f"{label}=已提供"
    state = str(value.get("state") or "").strip().lower()
    if state == "empty":
        return f"{label}=空（上游未提供请求上下文）"
    details: list[str] = []
    for key, label_text in (("parameter", "参数"), ("body", "请求体")):
        item = value.get(key)
        if not isinstance(item, dict):
            continue
        item_state = str(item.get("state") or "").strip().lower()
        if item_state == "present":
            details.append(f"{label_text}已提供")
        elif item_state == "empty":
            details.append(f"{label_text}为空")
    if value.get("raw_evidence_retained"):
        details.append("原始证据已保留")
    if not details:
        details.append("结构化状态已提供")
    return f"{label}=已提供（{'；'.join(details)}）"


def hook_data_fact(value: Any, label: str = "hook_data") -> str:
    """Render a safe hook-data summary and make retained evidence explicit."""
    if value in ("", None, [], {}):
        return ""
    if not isinstance(value, dict):
        return f"{label}=已提供"
    state = str(value.get("state") or "").strip().lower()
    fields: list[str] = []
    semantic = value.get("semantic_fields")
    if isinstance(semantic, dict):
        fields.extend(str(key) for key, item in semantic.items() if not isinstance(item, dict) or item.get("state") == "present")
    names = value.get("semantic_field_names")
    if isinstance(names, list):
        fields.extend(str(item) for item in names if item)
    if not fields:
        fields.extend(str(key) for key in value if str(key) in {"command", "cmd", "sql", "url", "class", "path", "expression"})
    details: list[str] = []
    if fields:
        details.append("关键字段 " + ", ".join(dict.fromkeys(fields)))
    indicators = value.get("indicator_categories")
    if isinstance(indicators, list) and indicators:
        details.append("特征 " + ", ".join(str(item) for item in indicators[:4]))
    if value.get("raw_evidence_retained"):
        details.append("原始证据已保留")
    if state == "empty":
        return f"{label}=空（上游未提供有效值）"
    return f"{label}=已提供（{'；'.join(details) if details else '结构化状态已提供'}）"


def join_facts(facts: list[str], fallback: str) -> str:
    compact = [item for item in facts if item]
    return "；".join(compact) + "。" if compact else fallback


def strip_terminal(value: Any) -> str:
    return str(value or "").strip().rstrip("。；; ")


# Ordered classification normalization. More specific / negated terms must come
# before their substrings (e.g. "非恶意" before "恶意", "恶意攻击" before "恶意",
# "真实攻击"/"真实事件" before "真实"). Shared by the agent and the LLM gateway
# validator so a Chinese-labeled classification is handled consistently instead
# of being downgraded to insufficient_evidence.
_CLASSIFICATION_MAP: list[tuple[str, str]] = [
    ("非恶意", "benign"),
    ("恶意攻击", "malicious"),
    ("恶意", "malicious"),
    ("真实攻击", "malicious"),
    ("真实事件", "malicious"),
    ("真实", "malicious"),
    ("误报", "benign"),
    ("良性", "benign"),
    ("可疑", "suspicious"),
    ("疑似", "suspicious"),
    ("证据不足", "insufficient_evidence"),
    ("malicious", "malicious"),
    ("suspicious", "suspicious"),
    ("benign", "benign"),
    ("insufficient_evidence", "insufficient_evidence"),
    ("insufficient", "insufficient_evidence"),
]


def normalize_classification(value: Any) -> str:
    text = str(value or "").strip().lower()
    for key, normalized in _CLASSIFICATION_MAP:
        if key in text:
            return normalized
    return "insufficient_evidence"
