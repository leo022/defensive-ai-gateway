from __future__ import annotations

import json
import re
from typing import Any

from .models import AgentResult, NormalizedEvent, ValidationFinding, ValidationResult, new_id
from .policy import PolicyEngine, SECRET_PATTERNS
from .skills import SkillManifest


_INJECTION_PATTERNS = (
    re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|system)\s+instructions?"),
    re.compile(r"(?i)(reveal|export|print)\s+(the\s+)?(system prompt|credentials?|secrets?|raw data)"),
    re.compile(r"忽略.{0,12}(之前|系统).{0,8}(指令|提示)"),
    re.compile(r"(导出|泄露|显示).{0,12}(凭证|密钥|系统提示|原始数据)"),
)


class Validator:
    name = "evidence_policy_validator"
    version = "2.0.0"

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

        untrusted_input = json.dumps({"entities": event.entities, "evidence": event.evidence}, ensure_ascii=False)
        if any(pattern.search(untrusted_input) for pattern in _INJECTION_PATTERNS):
            checks["prompt_injection"] = False
            findings.append(
                ValidationFinding(
                    "prompt_injection_detected",
                    "review",
                    "外部日志中检测到疑似提示注入文本；分析结果保留，但必须人工复核且不得自动流转。",
                    evidence_refs,
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
