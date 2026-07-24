from __future__ import annotations

import json
import re
from typing import Any, Iterator

from .models import (
    AgentResult,
    NormalizedEvent,
    ValidationEvidenceClue,
    ValidationFinding,
    ValidationResult,
    new_id,
)
from .policy import PolicyEngine, SECRET_PATTERNS
from .skills import SkillManifest


_INJECTION_PATTERNS = (
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|system)\s+instructions?"),
    re.compile(r"(?i)(reveal|export|print)\s+(the\s+)?(system prompt|credentials?|secrets?|raw data)"),
    re.compile(r"忽略.{0,12}(之前|系统).{0,8}(指令|提示)"),
    re.compile(r"(导出|泄露|显示).{0,12}(凭证|密钥|系统提示|原始数据)"),
)

_MAX_PROMPT_INJECTION_CLUES = 8
_MAX_PROMPT_INJECTION_SCAN_LEAVES = 512
_MAX_PROMPT_INJECTION_DEPTH = 16
_MAX_PROMPT_INJECTION_EXCERPT_CHARS = 240

# A prompt-injection marker means that untrusted telemetry may have attempted to
# influence the analysis model. It can be reviewed by a human, but it is not a
# generic bypass for evidence, output-contract, or action-policy failures.
MANUAL_REVIEW_CONTINUATION_CODES = frozenset({"prompt_injection_detected"})


def can_continue_after_manual_review(validation: ValidationResult) -> bool:
    """Return whether a review can enter the explicit human continuation path.

    The original Validator result stays immutable. Only a review caused solely
    by external prompt-injection text, with every other deterministic check
    passing, can be routed to a later approval decision after an analyst has
    documented what they verified.
    """
    if validation.status != "review":
        return False
    finding_codes = {finding.code for finding in validation.findings}
    if finding_codes != MANUAL_REVIEW_CONTINUATION_CODES:
        return False
    if not validation.checks or validation.checks.get("prompt_injection") is not False:
        return False
    return all(value for name, value in validation.checks.items() if name != "prompt_injection")


class Validator:
    name = "evidence_policy_validator"
    version = "2.1.0"

    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def validate(
        self, case_id: str, event: NormalizedEvent, result: AgentResult, skill: SkillManifest
    ) -> ValidationResult:
        findings: list[ValidationFinding] = []
        evidence_refs: list[str] = []
        for item in event.evidence:
            if not isinstance(item, dict):
                continue
            ref = item.get("ref")
            if not ref and isinstance(item.get("value"), dict):
                ref = item["value"].get("ref")
            if ref:
                evidence_refs.append(str(ref))
        checks = {
            "classification_contract": result.classification
            in {"malicious", "suspicious", "benign", "insufficient_evidence"},
            "confidence_contract": 0.0 <= result.confidence <= 1.0,
            "evidence_present": bool(event.evidence),
            "evidence_traceable": bool(evidence_refs),
            "evidence_grounded": result.evidence == event.evidence,
            "action_policy": True,
            "sensitive_output": True,
            "prompt_injection": True,
            "skill_boundary": "execute_production_action" in skill.blocked_tools,
        }

        if not checks["classification_contract"] or not checks["confidence_contract"]:
            findings.append(ValidationFinding("invalid_output_contract", "block", "Agent 输出不符合结构化分类或置信度契约。"))
        if event.severity in {"critical", "high"} and not event.evidence:
            findings.append(ValidationFinding("missing_high_risk_evidence", "block", "高风险 Case 缺少可追溯证据，禁止形成处置审批。"))
        elif not event.evidence:
            findings.append(ValidationFinding("missing_evidence", "review", "当前 Case 未携带归一化证据，需要人工补证。"))
        if event.severity in {"critical", "high"} and not checks["evidence_traceable"]:
            findings.append(ValidationFinding("untraceable_high_risk_evidence", "block", "高风险 Case 证据缺少不可变引用。"))
        if not checks["evidence_grounded"]:
            findings.append(
                ValidationFinding(
                    "ungrounded_agent_evidence",
                    "block",
                    "Agent 输出证据与归一化事实不一致，禁止形成处置审批。",
                    evidence_refs,
                )
            )

        for action in result.recommended_actions:
            if self.policy.requires_approval(action.action) and action.mode != "approve_required":
                checks["action_policy"] = False
                findings.append(
                    ValidationFinding(
                        "action_policy_violation",
                        "block",
                        f"高影响动作未进入审批模式：{action.action}",
                        evidence_refs,
                    )
                )
            if action.mode not in {"observe", "automated_read_only", "approve_required"}:
                checks["action_policy"] = False
                findings.append(ValidationFinding("unknown_action_mode", "block", f"未知动作模式：{action.mode}"))

        serialized_output = json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True)
        if any(pattern.search(serialized_output) for pattern in SECRET_PATTERNS):
            checks["sensitive_output"] = False
            findings.append(ValidationFinding("sensitive_output_detected", "block", "Agent 输出疑似包含未脱敏凭证或敏感标识。"))

        injection_clues = self._prompt_injection_clues(event)
        if not injection_clues:
            # Preserve the previous whole-document detector for unusual JSON
            # shapes (for example, a user-controlled key). The fallback never
            # reflects that key; it points the reviewer to the immutable alert.
            untrusted_input = json.dumps(
                {"entities": event.entities, "evidence": event.evidence}, ensure_ascii=False
            )
            if any(pattern.search(untrusted_input) for pattern in _INJECTION_PATTERNS):
                injection_clues = [
                    ValidationEvidenceClue(
                        evidence_ref=event.raw_ref,
                        field_path="untrusted_input",
                        excerpt="命中于未展开的外部结构化输入；请按证据引用复核。",
                    )
                ]
        if injection_clues:
            checks["prompt_injection"] = False
            findings.append(
                ValidationFinding(
                    "prompt_injection_detected",
                    "review",
                    "外部日志中检测到疑似提示注入文本；分析结果保留，但必须人工复核且不得自动流转。",
                    evidence_refs=self._unique_evidence_refs(injection_clues),
                    evidence_clues=injection_clues,
                )
            )

        if not checks["skill_boundary"]:
            findings.append(ValidationFinding("skill_boundary_missing", "block", "Skill 未显式禁止生产执行能力。"))

        status = "blocked" if any(f.severity == "block" for f in findings) else "review" if findings else "passed"
        return ValidationResult(
            validation_id=new_id("validation"),
            case_id=case_id,
            event_id=event.event_id,
            status=status,
            validator=self.name,
            validator_version=self.version,
            findings=findings,
            checks=checks,
        )

    def _prompt_injection_clues(self, event: NormalizedEvent) -> list[ValidationEvidenceClue]:
        """Locate prompt-injection patterns without re-emitting raw telemetry."""
        clues: list[ValidationEvidenceClue] = []
        leaves = self._untrusted_text_leaves(event)
        for field_path, value, evidence_ref in leaves:
            for pattern in _INJECTION_PATTERNS:
                match = pattern.search(value)
                if not match:
                    continue
                clues.append(
                    ValidationEvidenceClue(
                        evidence_ref=evidence_ref,
                        field_path=field_path,
                        excerpt=self._redacted_injection_excerpt(value, match),
                    )
                )
                break
            if len(clues) >= _MAX_PROMPT_INJECTION_CLUES:
                break
        return clues

    def _untrusted_text_leaves(
        self, event: NormalizedEvent
    ) -> Iterator[tuple[str, str, str]]:
        """Yield bounded textual leaves with the immutable evidence ref in scope."""
        seen_leaves = 0

        def walk(value: Any, path: str, evidence_ref: str, depth: int) -> Iterator[tuple[str, str, str]]:
            nonlocal seen_leaves
            if seen_leaves >= _MAX_PROMPT_INJECTION_SCAN_LEAVES or depth > _MAX_PROMPT_INJECTION_DEPTH:
                return
            if isinstance(value, str):
                seen_leaves += 1
                yield path, value, evidence_ref
                return
            if isinstance(value, dict):
                for key, item in value.items():
                    if seen_leaves >= _MAX_PROMPT_INJECTION_SCAN_LEAVES:
                        return
                    yield from walk(item, self._field_path(path, key), evidence_ref, depth + 1)
                return
            if isinstance(value, list):
                for index, item in enumerate(value):
                    if seen_leaves >= _MAX_PROMPT_INJECTION_SCAN_LEAVES:
                        return
                    yield from walk(item, f"{path}[{index}]", evidence_ref, depth + 1)

        yield from walk(event.entities, "entities", event.raw_ref, 0)
        for index, evidence in enumerate(event.evidence):
            if seen_leaves >= _MAX_PROMPT_INJECTION_SCAN_LEAVES:
                return
            if not isinstance(evidence, dict):
                continue
            yield from walk(
                evidence,
                f"evidence[{index}]",
                self._evidence_ref(evidence, event.raw_ref),
                0,
            )

    @staticmethod
    def _field_path(prefix: str, key: Any) -> str:
        key_text = str(key)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_text):
            return f"{prefix}.{key_text}"
        # A dynamic key can itself contain an instruction. Preserve the fact
        # that it was an external key without reflecting it as a field path.
        return f"{prefix}.[untrusted_key]"

    @staticmethod
    def _evidence_ref(evidence: dict[str, Any], fallback: str) -> str:
        ref = evidence.get("ref")
        if not ref and isinstance(evidence.get("value"), dict):
            ref = evidence["value"].get("ref")
        return str(ref or fallback)

    @staticmethod
    def _unique_evidence_refs(clues: list[ValidationEvidenceClue]) -> list[str]:
        refs: list[str] = []
        for clue in clues:
            if clue.evidence_ref and clue.evidence_ref not in refs:
                refs.append(clue.evidence_ref)
        return refs

    def _redacted_injection_excerpt(self, value: str, match: re.Match[str]) -> str:
        start = max(0, match.start() - 64)
        if start:
            # Do not present a cropped tail of an unrelated word as evidence
            # context; keep the bounded excerpt readable for the reviewer.
            word_boundary = value.find(" ", start)
            if word_boundary != -1 and word_boundary < match.start():
                start = word_boundary + 1
        end = min(len(value), match.end() + 128)
        excerpt = f"{'...' if start else ''}{value[start:end]}{'...' if end < len(value) else ''}"
        redacted = self.policy.redact({"external_log_excerpt": excerpt})
        safe_excerpt = re.sub(r"\s+", " ", str(redacted.get("external_log_excerpt", ""))).strip()
        if len(safe_excerpt) <= _MAX_PROMPT_INJECTION_EXCERPT_CHARS:
            return safe_excerpt
        return f"{safe_excerpt[: _MAX_PROMPT_INJECTION_EXCERPT_CHARS - 3]}..."
