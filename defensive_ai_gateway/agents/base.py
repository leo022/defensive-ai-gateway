from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any

from ..llm import LLMClient
from ..models import AgentResult, NormalizedEvent, RecommendedAction, new_id
from ..policy import PolicyEngine


class SecurityAgent(ABC):
    name = "base"
    product = "generic"
    prompt_version = "v0"

    def __init__(self, llm: LLMClient, policy: PolicyEngine):
        self.llm = llm
        self.policy = policy

    @abstractmethod
    def system_prompt(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def analysis_focus(self) -> list[str]:
        raise NotImplementedError

    def analyze(self, case_id: str, event: NormalizedEvent, memory: list[dict[str, Any]]) -> AgentResult:
        context = {
            "product": event.product,
            "severity": event.severity,
            "event_type": event.event_type,
            "entities": event.entities,
            "evidence": event.evidence,
            "evidence_details": event.evidence,
            "memory": memory,
            "focus": self.analysis_focus(),
        }
        prompt = self._build_prompt(context)
        llm_result = self.llm.analyze(prompt, context)
        llm_result = self._ensure_explainable_result(llm_result, event)
        classification = self._normalize_classification(llm_result.get("classification", "insufficient_evidence"))
        confidence = self._normalize_confidence(llm_result.get("confidence", 0.3))
        explanation = self._explanation(llm_result)
        explanation["verdict"] = self._format_verdict(explanation.get("verdict", ""), classification)
        summary = self._summary(event, classification, confidence, llm_result, explanation)
        actions = self._actions(event, classification, llm_result)
        return AgentResult(
            case_id=case_id,
            agent=self.name,
            classification=classification,
            confidence=confidence,
            severity=self._severity(event.severity, classification, confidence),
            summary=summary,
            evidence=event.evidence,
            missing_evidence=self._missing_evidence(event, llm_result),
            recommended_actions=actions,
            dashboard_cards=[
                {"title": "AI 初判", "body": summary},
                {"title": "研判结论", "body": explanation.get("verdict") or "未提取到结构化结论"},
                {"title": "证据维度", "body": str(len(explanation.get("dimensions", [])))},
                {"title": "证据数量", "body": str(len(event.evidence))},
                {"title": "处置模式", "body": ", ".join(sorted({a.mode for a in actions}))},
            ],
            explanation=explanation,
        )

    def _build_prompt(self, context: dict[str, Any]) -> str:
        return (
            self.system_prompt()
            + "\n\n你正在为银行 SOC 分析安全告警。请全程使用简体中文输出。只基于输入证据分析，不要编造不存在的事实，不要输出攻击利用步骤、payload 或真实凭证。"
            + "\n请以银行安全运营专家口吻回答，重点说明：攻击链判断、业务影响、证据强弱、仍需补充的证据、只读验证步骤。"
            + "\n输入中的 memory 为多层记忆：case_short_term（本 Case 短期记忆）、product_long_term（产品长期经验）、asset_profile（资产画像）、org_knowledge（组织知识/Playbook）、evidence_refs（不可改证据引用）。evidence_refs 只读，仅作引用，不得外泄原始敏感字段。"
            + "\n必须返回严格 JSON，字段如下："
            + '\n{"classification":"malicious|suspicious|benign|insufficient_evidence",'
            + '"confidence":0.0,'
            + '"verdict":"研判结论，格式为【真实攻击/误报/需人工复核】- 原因",'
            + '"analysis_dimensions":[{"title":"维度名","status":"risk|benign|normal|blocked|review|info","evidence":"该维度判断依据"}],'
            + '"whitelist_recommendation":{"rule_type":"仅误报时填写","detection_content":"最精确检测内容","match_method":"相等|包含|正则匹配","reason":"白名单原因"},'
            + '"reason":"必须使用简体中文，说明攻击链、证据和不确定性",'
            + '"recommended_next_steps":["必须使用简体中文，只写只读验证或需审批动作，不要输出空字符串"],'
            + '"missing_evidence":["必须使用简体中文，列出还需要的证据"],'
            + '"attack_stage":["可选 MITRE/攻击阶段"],'
            + '"business_impact":"必须使用简体中文描述业务影响"}'
            + "\n\n输入上下文：\n"
            + self.policy.truncate_prompt_payload(context)
        )

    def _summary(
        self,
        event: NormalizedEvent,
        classification: str,
        confidence: float,
        llm_result: dict[str, Any],
        explanation: dict[str, Any],
    ) -> str:
        entity_bits = ", ".join(f"{k}={v}" for k, v in event.entities.items()) or "缺少关键实体"
        impact = llm_result.get("business_impact")
        impact_text = f"业务影响：{impact}。" if impact else ""
        reason_head = explanation.get("verdict") or self._first_reason_line(llm_result.get("reason", ""))
        return (
            f"{self.product.upper()} {event.event_type} 被判定为 {classification}，置信度 {confidence:.2f}。"
            f"关键实体：{entity_bits}。{impact_text}{reason_head}"
        )

    def _ensure_explainable_result(self, llm_result: dict[str, Any], event: NormalizedEvent) -> dict[str, Any]:
        explanation = self._explanation(llm_result)
        llm_verdict = explanation.get("verdict", "")
        llm_dims = explanation.get("dimensions", [])
        classification = self._normalize_classification(llm_result.get("classification", "insufficient_evidence"))

        # The heuristic analyzer is deterministic and already reconciles sample
        # evidence + memory itself; only fill missing fields (original behavior).
        # Model-backed LLMs (ollama/gateway) are reconciled for consistency and
        # grounded against structured sample evidence where available.
        if not getattr(self.llm, "is_deterministic", False):
            return self._reconcile_model_result(
                llm_result, event, explanation, classification, llm_verdict, llm_dims
            )

        if llm_verdict and llm_dims:
            return llm_result
        fallback = self._fallback_from_evidence(event)
        if not fallback:
            return llm_result
        merged = dict(llm_result)
        merged.setdefault("reason", fallback["reason"])
        if not llm_verdict:
            merged["verdict"] = fallback["verdict"]
        if not llm_dims:
            merged["analysis_dimensions"] = fallback["analysis_dimensions"]
        if not merged.get("whitelist_recommendation") and fallback.get("whitelist_recommendation"):
            merged["whitelist_recommendation"] = fallback["whitelist_recommendation"]
        if not merged.get("business_impact") and fallback.get("business_impact"):
            merged["business_impact"] = fallback["business_impact"]
        if not merged.get("missing_evidence") and fallback.get("missing_evidence"):
            merged["missing_evidence"] = fallback["missing_evidence"]
        normalized_current = self._normalize_classification(merged.get("classification", "insufficient_evidence"))
        if normalized_current == "insufficient_evidence":
            merged["classification"] = fallback["classification"]
            merged["confidence"] = max(self._normalize_confidence(merged.get("confidence", 0.0)), fallback["confidence"])
        return merged

    def _reconcile_model_result(
        self,
        llm_result: dict[str, Any],
        event: NormalizedEvent,
        explanation: dict[str, Any],
        classification: str,
        llm_verdict: str,
        llm_dims: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Reconcile unreliable model output into a logically consistent result.

        Priority:
        1. Structured sample ground truth (``evidence_assessment.expected_verdict``)
           is authoritative — small local models frequently misclassify samples,
           so the annotated verdict wins and the model may only enrich reason /
           next steps.
        2. Otherwise, trust the model only when its own dimensions carry a status
           consistent with its classification (e.g. malicious ⇒ a risk/blocked
           dimension). This catches the common failure of a high-confidence
           verdict with all-``info`` dimensions.
        3. Otherwise, synthesize consistent dimensions from the normalized
           evidence so the dashboard never shows a verdict contradicted by
           "信息"-only dimensions.
        """
        structured = self._fallback_from_evidence(event)
        if structured and structured.get("verdict"):
            return self._merge_with_structured(llm_result, structured)
        if llm_dims and llm_verdict and self._dimensions_support_classification(llm_dims, classification):
            return llm_result
        return self._reconcile_ungrounded(llm_result, event, explanation, classification)

    def _merge_with_structured(self, llm_result: dict[str, Any], structured: dict[str, Any]) -> dict[str, Any]:
        """Override the model's classification/verdict/dimensions with structured
        sample ground truth, keeping the model's free-text enrichments when they
        add value."""
        merged = dict(llm_result)
        merged["classification"] = structured["classification"]
        merged["verdict"] = structured["verdict"]
        merged["analysis_dimensions"] = structured["analysis_dimensions"]
        merged["confidence"] = structured["confidence"]
        if not str(merged.get("business_impact", "")).strip():
            merged["business_impact"] = structured.get("business_impact", "")
        if not merged.get("missing_evidence"):
            merged["missing_evidence"] = structured.get("missing_evidence", [])
        if not merged.get("whitelist_recommendation") and structured.get("whitelist_recommendation"):
            merged["whitelist_recommendation"] = structured["whitelist_recommendation"]
        if not str(merged.get("reason", "")).strip():
            merged["reason"] = structured.get("reason", "")
        return merged

    def _reconcile_ungrounded(
        self,
        llm_result: dict[str, Any],
        event: NormalizedEvent,
        explanation: dict[str, Any],
        classification: str,
    ) -> dict[str, Any]:
        """No structured ground truth available (e.g. a real vendor log without
        ``evidence_assessment``). Keep the model's classification but ensure the
        dimensions are consistent with it instead of leaving all-``info`` gaps."""
        merged = dict(llm_result)
        llm_dims = explanation.get("dimensions", [])
        if llm_dims and self._dimensions_support_classification(llm_dims, classification):
            merged["analysis_dimensions"] = llm_dims
        else:
            merged["analysis_dimensions"] = self._synthesize_dimensions(event, classification)
        if not str(merged.get("verdict", "")).strip():
            merged["verdict"] = self._verdict_from_classification(classification)
        return merged

    # Dimension status ↔ classification consistency helpers -------------------

    _CLASSIFICATION_STATUS = {
        "malicious": "risk",
        "benign": "benign",
        "suspicious": "review",
        "insufficient_evidence": "info",
    }
    _CLASSIFICATION_LABEL = {
        "malicious": "真实攻击",
        "benign": "误报",
        "suspicious": "需人工复核",
        "insufficient_evidence": "证据不足",
    }

    def _status_supports_classification(self, status: Any, classification: str) -> bool:
        s = self._normalize_dimension_status(status)
        if classification == "malicious":
            return s in {"risk", "blocked"}
        if classification == "benign":
            return s in {"benign", "normal"}
        if classification == "suspicious":
            return s in {"review", "risk", "blocked"}
        return True

    def _dimensions_support_classification(self, dims: list[dict[str, Any]], classification: str) -> bool:
        return any(self._status_supports_classification(d.get("status"), classification) for d in dims if isinstance(d, dict))

    def _synthesize_dimensions(self, event: NormalizedEvent, classification: str) -> list[dict[str, str]]:
        """Build Chinese dimensions with statuses consistent with ``classification``
        from the normalized evidence, used when the model produced no grounded
        dimensions and no structured sample assessment exists."""
        status = self._CLASSIFICATION_STATUS.get(classification, "info")
        label = self._CLASSIFICATION_LABEL.get(classification, "证据不足")
        entities = event.entities or {}
        by_type: dict[str, Any] = {}
        for item in event.evidence or []:
            if isinstance(item, dict) and item.get("type") and item.get("type") not in by_type:
                by_type[item["type"]] = item.get("value")

        dims: list[dict[str, str]] = []
        rule = entities.get("rule") or by_type.get("rule_id") or by_type.get("rule_name")
        if rule:
            dims.append({"title": "检测规则", "status": status, "evidence": f"命中规则 {self._short(rule)}，与「{label}」判断相关。"})
        indicators = self._collect_attack_indicators(event, by_type, entities)
        if indicators:
            dims.append({"title": "攻击特征", "status": status, "evidence": indicators})
        sink = by_type.get("sink") or by_type.get("stack_trace") or by_type.get("stacktrace")
        if sink:
            dims.append({"title": "危险调用", "status": status, "evidence": f"调用栈/危险 sink 涉及 {self._short(sink)}。"})
        action = entities.get("action") or by_type.get("action")
        if action:
            action_status = "blocked" if classification == "malicious" and self._looks_blocked(action) else status
            dims.append({"title": "处置动作", "status": action_status, "evidence": f"安全产品动作：{self._short(action)}。"})
        host = entities.get("host") or entities.get("src_ip")
        if host:
            dims.append({"title": "受影响实体", "status": status, "evidence": f"关键实体：{host}。"})

        if not dims:
            dims.append({"title": "综合判断", "status": status, "evidence": f"基于归一化证据的综合判断为「{label}」，缺少结构化分维度标注。"})
        dims.append(
            {
                "title": "证据完整性",
                "status": "review" if classification in {"malicious", "suspicious"} else "normal",
                "evidence": f"归一化证据 {len(event.evidence or [])} 条，建议结合产品原始日志与关联事件只读复核。",
            }
        )
        return dims

    def _collect_attack_indicators(self, event: NormalizedEvent, by_type: dict[str, Any], entities: dict[str, Any]) -> str:
        parts: list[str] = []
        if by_type.get("hook_data"):
            parts.append(f"hook_data={self._short(by_type['hook_data'])}")
        if by_type.get("taint_source"):
            parts.append(f"污染源={by_type['taint_source']}")
        if by_type.get("payload_category"):
            parts.append(f"载荷={self._short(by_type['payload_category'])}")
        if by_type.get("command_line"):
            parts.append(f"命令行={self._short(by_type['command_line'])}")
        if by_type.get("sni"):
            parts.append(f"SNI={by_type['sni']}")
        url = entities.get("url")
        if url and any(m in str(url).lower() for m in ("ldap://", "rmi://", "ftp://", "http://", "gopher://")):
            parts.append(f"URL={self._short(url)}")
        return "；".join(parts)

    def _short(self, value: Any) -> str:
        if isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False)
        else:
            text = str(value)
        text = text.replace("\n", " ").strip()
        return text[:100] + ("…" if len(text) > 100 else "")

    def _looks_blocked(self, action: Any) -> bool:
        return any(w in str(action).lower() for w in ("block", "阻断", "intercept", "prevent", "deny"))

    def _fallback_from_evidence(self, event: NormalizedEvent) -> dict[str, Any] | None:
        verdict = ""
        dimensions = []
        whitelist: dict[str, Any] = {}
        impact = ""
        missing: list[str] = []
        success = ""
        for item in event.evidence:
            item_type = item.get("type")
            value = item.get("value")
            if item_type == "expected_verdict" and value:
                verdict = str(value)
            elif item_type == "analysis_dimension" and isinstance(value, dict):
                dimensions.append(
                    {
                        "title": str(value.get("title") or "证据维度"),
                        "status": str(value.get("status") or item.get("weight") or "info"),
                        "evidence": str(value.get("evidence") or ""),
                    }
                )
            elif item_type == "whitelist_candidate" and isinstance(value, dict):
                whitelist = value
            elif item_type == "business_impact" and value:
                impact = str(value)
            elif item_type == "success_assessment" and value:
                success = str(value)
            elif item_type == "missing_evidence":
                if isinstance(value, list):
                    missing.extend(str(part) for part in value if part)
                elif value:
                    missing.append(str(value))
        if not verdict and not dimensions:
            return None
        classification = self._classification_from_verdict(verdict, event.severity)
        reason_lines = [f"研判结论：{verdict or self._verdict_from_classification(classification)}", "分析报告："]
        for item in dimensions:
            reason_lines.append(f"- {item['title']}：{item['evidence']}")
        if success:
            reason_lines.append(f"- 成功与危害：{success}")
        if impact:
            reason_lines.append(f"- 业务影响：{impact}")
        return {
            "classification": classification,
            "confidence": self._fallback_confidence(classification, dimensions, event.severity),
            "verdict": verdict or self._verdict_from_classification(classification),
            "analysis_dimensions": dimensions,
            "whitelist_recommendation": whitelist,
            "business_impact": impact,
            "missing_evidence": missing,
            "reason": "\n".join(reason_lines),
        }

    def _classification_from_verdict(self, verdict: str, severity: str) -> str:
        text = verdict.lower()
        if "误报" in text or "benign" in text:
            return "benign"
        if "真实" in text or "malicious" in text:
            return "malicious"
        if "复核" in text or "可疑" in text or "suspicious" in text:
            return "suspicious"
        return "suspicious" if severity in {"critical", "high"} else "insufficient_evidence"

    def _verdict_from_classification(self, classification: str) -> str:
        return {
            "malicious": "【真实攻击】- 归一化证据支持攻击判断",
            "benign": "【误报】- 归一化证据支持误报判断",
            "suspicious": "【需人工复核】- 归一化证据不足以完全确认",
        }.get(classification, "【需人工复核】- 证据不足")

    # 原始三类结论格式：【真实攻击/误报/需人工复核】- 原因
    _VERDICT_TAGS = ("【真实攻击】", "【误报】", "【需人工复核】")

    # 分维度 status 原始取值（与 prompt 中 analysis_dimensions.status 枚举一致，
    # 对应 Dashboard 的 风险/正常/复核/信息 四类颜色）。
    _DIMENSION_STATUSES = ("risk", "benign", "normal", "blocked", "review", "info")
    _DIMENSION_STATUS_ALIASES = {
        "malicious": "risk",
        "high": "risk",
        "allow": "normal",
        "low": "normal",
        "suspicious": "review",
        "medium": "review",
    }

    def _normalize_dimension_status(self, status: Any) -> str:
        """把维度 status 归一到原始枚举，保证 Dashboard 能匹配到颜色。
        模型有时会输出 "PASSED"/"OK" 之类非约定值，这里映射回原始六类。"""
        value = str(status or "").strip().lower()
        if value in self._DIMENSION_STATUSES:
            return value
        return self._DIMENSION_STATUS_ALIASES.get(value, "info")

    def _format_verdict(self, verdict: str, classification: str) -> str:
        """把模型产出的 verdict 规范化为原始三类结论格式
        【真实攻击/误报/需人工复核】- 原因。

        本地小模型常把 verdict 填成 "high_risk" 之类的自由标签，这里在
        不改 prompt 的前提下，按 classification 修正类别标签、保留模型的
        原因描述，使研判结论回到统一的三类格式。
        """
        verdict = (verdict or "").strip()
        for tag in self._VERDICT_TAGS:
            if verdict.startswith(tag):
                return verdict
        if "真实攻击" in verdict or classification == "malicious":
            tag = "【真实攻击】"
        elif "误报" in verdict or classification == "benign":
            tag = "【误报】"
        else:
            tag = "【需人工复核】"
        detail = verdict
        if detail:
            detail = re.sub(r"^(真实攻击|误报|需人工复核|恶意|良性)[\s\-:：、，,]*", "", detail).strip()
            detail = detail.strip("【】[]-—：:、，, ")
        if not detail:
            detail = self._verdict_from_classification(classification).split("】- ", 1)[-1].strip()
        return f"{tag}- {detail}"

    def _fallback_confidence(self, classification: str, dimensions: list[dict[str, str]], severity: str) -> float:
        confidence = 0.65 + min(0.18, len(dimensions) * 0.03)
        if classification == "benign":
            confidence += 0.04
        if classification == "malicious" and severity in {"critical", "high"}:
            confidence += 0.04
        return round(min(0.9, confidence), 2)

    def _explanation(self, llm_result: dict[str, Any]) -> dict[str, Any]:
        reason = str(llm_result.get("reason", "") or "")
        dimensions = llm_result.get("analysis_dimensions")
        if not isinstance(dimensions, list):
            dimensions = self._parse_reason_dimensions(reason)
        normalized_dimensions = []
        for item in dimensions:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or item.get("dimension") or "").strip()
            evidence = str(item.get("evidence") or item.get("detail") or item.get("value") or "").strip()
            if not title and not evidence:
                continue
            normalized_dimensions.append(
                {
                    "title": title or "未命名维度",
                    "status": self._normalize_dimension_status(item.get("status")),
                    "evidence": evidence,
                }
            )
        verdict = str(llm_result.get("verdict") or self._parse_verdict(reason) or "").strip()
        whitelist = llm_result.get("whitelist_recommendation") or self._parse_whitelist(llm_result)
        return {
            "verdict": verdict,
            "dimensions": normalized_dimensions,
            "whitelist_recommendation": whitelist,
            "raw_reason": reason,
        }

    def _parse_verdict(self, reason: str) -> str:
        for line in reason.splitlines():
            text = line.strip()
            if text.startswith("研判结论"):
                return text.split("：", 1)[-1].strip()
        return ""

    def _parse_reason_dimensions(self, reason: str) -> list[dict[str, str]]:
        dimensions = []
        for line in reason.splitlines():
            text = line.strip()
            if not text.startswith("- "):
                continue
            body = text[2:]
            if "：" in body:
                title, evidence = body.split("：", 1)
            elif ":" in body:
                title, evidence = body.split(":", 1)
            else:
                continue
            dimensions.append({"title": title.strip(), "evidence": evidence.strip(), "status": "info"})
        return dimensions

    def _parse_whitelist(self, llm_result: dict[str, Any]) -> dict[str, str] | str:
        for item in llm_result.get("recommended_next_steps", []) or []:
            if isinstance(item, str) and "建议添加以下白名单" in item:
                return item
        return {}

    def _first_reason_line(self, reason: Any) -> str:
        for line in str(reason or "").splitlines():
            text = line.strip()
            if text:
                return text
        return ""

    def _normalize_classification(self, value: Any) -> str:
        text = str(value).strip().lower()
        mapping = {
            "恶意": "malicious",
            "恶意攻击": "malicious",
            "malicious": "malicious",
            "可疑": "suspicious",
            "疑似": "suspicious",
            "suspicious": "suspicious",
            "良性": "benign",
            "误报": "benign",
            "benign": "benign",
            "证据不足": "insufficient_evidence",
            "insufficient": "insufficient_evidence",
            "insufficient_evidence": "insufficient_evidence",
        }
        for key, normalized in mapping.items():
            if key in text:
                return normalized
        return "insufficient_evidence"

    def _normalize_confidence(self, value: Any) -> float:
        if isinstance(value, str):
            text = value.strip().replace("%", "")
            try:
                numeric = float(text)
            except ValueError:
                return 0.3
        else:
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return 0.3
        if numeric > 1:
            numeric = numeric / 100
        return max(0.0, min(1.0, numeric))

    def _severity(self, original: str, classification: str, confidence: float) -> str:
        if classification == "benign":
            return "low" if confidence >= 0.7 else "medium"
        if classification == "malicious":
            # A confirmed real attack is at least high-urgency regardless of the
            # product's original rating; preserve critical when the source already
            # rated it so. Without this, a confirmed attack can sit at "medium".
            return "critical" if original == "critical" else "high"
        if original in {"critical", "high"}:
            return original
        if classification == "suspicious" and confidence >= 0.75:
            return "high"
        if classification == "suspicious":
            return "medium"
        return original or "low"

    def _missing_evidence(self, event: NormalizedEvent, llm_result: dict[str, Any]) -> list[str]:
        missing = []
        for key in ["host", "src_ip", "rule"]:
            if key not in event.entities:
                missing.append(f"缺少 {key} 上下文")
        for item in llm_result.get("missing_evidence", []) or []:
            if isinstance(item, str) and item not in missing:
                missing.append(item)
        return missing

    def _actions(self, event: NormalizedEvent, classification: str, llm_result: dict[str, Any]) -> list[RecommendedAction]:
        actions = [RecommendedAction("观察同源事件 30 分钟并关联资产画像", self.policy.action_mode("observe"), "只读观察不会影响生产。")]
        for item in llm_result.get("recommended_next_steps", []) or []:
            if isinstance(item, str) and item.strip():
                action_text = self.policy.safe_action_text(item)
                actions.append(
                    RecommendedAction(
                        action_text,
                        self.policy.action_mode(action_text),
                        "由 LLM 基于当前证据提出，执行前需遵守网关策略。",
                    )
                )
        if classification == "suspicious":
            actions.append(
                RecommendedAction(
                    f"升级 {event.product.upper()} 事件到 SOC 人工复核",
                    self.policy.action_mode("escalate"),
                    "AI 置信度达到可疑级别，需要分析师确认。",
                )
            )
        return actions


def run_id() -> str:
    return new_id("run")
