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
