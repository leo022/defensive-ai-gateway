from __future__ import annotations

import copy
import json
import re
from typing import Any

from .config import PolicyConfig


SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[a-z0-9._\-]+"),
    re.compile(r"(?i)(api[_-]?key[=:]\s*)[a-z0-9._\-]+"),
    re.compile(r"(?i)(password[=:]\s*)[^,\s]+"),
    re.compile(r"\b\d{15,18}[0-9Xx]\b"),
]


class PolicyEngine:
    def __init__(self, config: PolicyConfig):
        self.config = config

    def redact(self, value: Any) -> Any:
        cloned = copy.deepcopy(value)
        return self._redact_any(cloned)

    def _redact_any(self, value: Any) -> Any:
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            for key, item in value.items():
                if key.lower() in {f.lower() for f in self.config.redact_fields}:
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
        lowered = action.lower()
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
