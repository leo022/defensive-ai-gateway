from __future__ import annotations

import re
from collections.abc import Iterable

from .models import RecommendedAction


ACTION_STAGE_ORDER = {
    "verify": 10,
    "coordinate": 20,
    "contain": 30,
    "eradicate": 40,
    "recover": 50,
    "monitor": 60,
}

_LEADING_MARKER = re.compile(
    r"^\s*(?:(?:步骤|step)\s*)?"
    r"(?:[（(]?\d{1,3}[）)]?|[一二三四五六七八九十]{1,3})"
    r"\s*[\.、:：)）-]\s*",
    re.IGNORECASE,
)
_LEADING_BULLET = re.compile(r"^\s*[-*•·]+\s*")


def normalize_action_text(value: str) -> str:
    """Remove model-authored list markers while preserving the action itself."""
    text = str(value or "").strip()
    previous = None
    while text and text != previous:
        previous = text
        text = _LEADING_BULLET.sub("", text)
        text = _LEADING_MARKER.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def action_stage(value: str) -> str:
    text = normalize_action_text(value).casefold()
    # Recovery must be tested before containment because phrases such as
    # "解除主机隔离" contain both concepts.
    if any(term in text for term in ("恢复", "回滚", "解除隔离", "解除封禁", "解除阻断", "业务恢复")):
        return "recover"
    if any(term in text for term in ("封禁", "阻断", "隔离", "禁用", "切断", "下线", "遏制", "限制访问")):
        return "contain"
    if any(term in text for term in ("修复", "补丁", "加固", "升级版本", "清除", "根除", "变更策略", "调整规则")):
        return "eradicate"
    if any(term in text for term in ("升级", "通知", "工单", "协同", "上报", "联动")):
        return "coordinate"
    if any(term in text for term in ("监控", "观察", "持续关注", "跟踪", "复测", "验证处置")):
        return "monitor"
    return "verify"


def normalize_action_plan(actions: Iterable[RecommendedAction]) -> list[RecommendedAction]:
    """Return a deduplicated, operationally ordered response plan."""
    normalized: list[tuple[int, int, RecommendedAction]] = []
    seen: set[str] = set()
    for source_index, item in enumerate(actions):
        text = normalize_action_text(item.action)
        key = re.sub(r"[\s，。；、,.;:：]+", "", text).casefold()
        if not text or key in seen:
            continue
        seen.add(key)
        stage = action_stage(text)
        normalized.append(
            (
                ACTION_STAGE_ORDER[stage],
                source_index,
                RecommendedAction(
                    action=text,
                    mode=item.mode,
                    rationale=str(item.rationale or "").strip(),
                    rollback=str(item.rollback or "").strip(),
                    stage=stage,
                ),
            )
        )
    normalized.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in normalized]
