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
