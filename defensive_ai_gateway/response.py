from __future__ import annotations

import hashlib

from .models import AgentResult, ApprovalRequest, RecommendedAction, ValidationResult
from .policy import PolicyEngine


class ResponseAdvisor:
    name = "controlled_response_advisor"
    version = "2.0.0"

    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def prepare(self, event_id: str, result: AgentResult, validation: ValidationResult) -> list[ApprovalRequest]:
        # Only a clean Validator pass may enter the approval queue. A review finding
        # (including prompt injection) remains visible on the Case but cannot be
        # turned into an authorization request until an analyst resolves it.
        if validation.status != "passed":
            return []
        actions = list(result.recommended_actions)
        if result.classification == "malicious" and result.severity in {"critical", "high"} and result.confidence >= 0.75:
            product = result.agent.split("-", 1)[0].lower()
            templates = {
                "waf": ("评估临时封禁恶意来源并加严命中规则", "撤销临时来源封禁并恢复变更前 WAF 规则版本。"),
                "hips": ("评估隔离受影响主机并保全现场", "解除主机隔离并恢复审批前网络访问策略。"),
                "ndr": ("评估阻断恶意通信并隔离相关网络会话", "撤销临时阻断策略并恢复审批前网络访问控制。"),
                "rasp": ("评估切换 RASP 阻断策略并通知应用 Owner", "恢复审批前 RASP 策略版本并确认应用健康状态。"),
                "siem": ("发起高风险事件响应工单并请求跨产品处置审批", "取消未执行的响应任务；已执行项分别按原系统回滚记录恢复。"),
            }
            if product in templates:
                action, rollback = templates[product]
                actions.append(
                    RecommendedAction(
                        action=action,
                        mode="approve_required",
                        rationale="高风险真实攻击达到受控处置建议阈值；该建议仅创建审批，不执行生产动作。",
                        rollback=rollback,
                    )
                )
        requests: list[ApprovalRequest] = []
        for action in actions:
            if self.policy.requires_approval(action.action):
                action.mode = "approve_required"
            if action.mode != "approve_required":
                continue
            rollback = action.rollback.strip() or "由执行系统记录变更前状态；出现业务异常时停止动作并恢复变更前配置。"
            digest = hashlib.sha256(f"{result.case_id}\0{event_id}\0{action.action}".encode("utf-8")).hexdigest()[:20]
            requests.append(
                ApprovalRequest(
                    approval_id=f"approval_{digest}",
                    case_id=result.case_id,
                    event_id=event_id,
                    action=action.action,
                    rationale=action.rationale,
                    rollback=rollback,
                )
            )
        return requests
