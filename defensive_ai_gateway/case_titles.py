from __future__ import annotations

import re
from typing import Any


_VERDICT_HEADING = re.compile(
    r"^(?:\*\*|__)?\s*研判结论\s*[：:]\s*(?:\*\*|__)?\s*"
)
_VERDICT_TAG = re.compile(
    r"^【(真实攻击|真实事件|误报|需人工复核)】[\s\-—:：、，,]*"
)
_PLAIN_VERDICT_TAG = re.compile(
    r"^(?:真实攻击|真实事件|误报|需人工复核|恶意|良性)[\s\-—:：、，,]*"
)
_NORMALIZED_TAGS = {
    "真实攻击": "【真实攻击】",
    "真实事件": "【真实攻击】",
    "误报": "【误报】",
    "需人工复核": "【需人工复核】",
}
_FALLBACK_DETAILS = {
    "malicious": "归一化证据支持攻击判断",
    "benign": "归一化证据支持误报判断",
    "suspicious": "归一化证据不足以完全确认",
}


def _strip_outer_emphasis(value: str) -> str:
    for marker in ("**", "__"):
        if (
            len(value) >= len(marker) * 2
            and value.startswith(marker)
            and value.endswith(marker)
        ):
            return value[len(marker) : -len(marker)].strip()
    return value


def _split_verdict(value: Any) -> tuple[str, str]:
    text = str(value or "").strip()
    declared_tag = ""
    for _ in range(8):
        previous = text
        text = _VERDICT_HEADING.sub("", text, count=1).strip()
        text = _strip_outer_emphasis(text)
        tag_match = _VERDICT_TAG.match(text)
        if tag_match:
            if not declared_tag:
                declared_tag = _NORMALIZED_TAGS[tag_match.group(1)]
            text = text[tag_match.end() :].strip()
        else:
            text = _PLAIN_VERDICT_TAG.sub("", text, count=1).strip()
        if text == previous:
            break
    return declared_tag, _strip_outer_emphasis(text)


def normalize_case_verdict(value: Any, classification: str) -> str:
    source = str(value or "").strip()
    declared_tag, detail = _split_verdict(source)
    if declared_tag:
        tag = declared_tag
    elif (
        "真实攻击" in source
        or "真实事件" in source
        or classification == "malicious"
    ):
        tag = "【真实攻击】"
    elif "误报" in source or classification == "benign":
        tag = "【误报】"
    else:
        tag = "【需人工复核】"
    if not detail:
        detail = _FALLBACK_DETAILS.get(classification, "证据不足")
    return f"{tag}- {detail}"


def compact_case_title(value: Any, event_type: str = "") -> str:
    declared_tag, detail = _split_verdict(value)
    if not detail:
        declared_tag = declared_tag or "【需人工复核】"
        detail = f"{event_type or '安全告警'}关键证据不足"
    title = f"{declared_tag}- {detail}" if declared_tag else detail
    title = re.split(r"[。\n]", title, maxsplit=1)[0].strip()
    if len(title) > 72:
        title = title[:71].rstrip("，,；;：:、 ") + "…"
    return title
