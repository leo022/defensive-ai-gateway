from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any

from ..llm import LLMClient
from ..models import AgentResult, NormalizedEvent, RecommendedAction, new_id
from ..policy import PolicyEngine
from .evidence_helpers import fact, join_facts, normalize_classification, short_text, strip_terminal


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

    def report_outline(self) -> list[str]:
        """Product-specific report headings used by prompts and fallbacks.

        The JSON contract stays stable for local, Ollama, and enterprise LLM
        gateways. These headings only guide the content of ``reason`` and
        ``analysis_dimensions`` so every backend produces the same analyst view.
        """
        return ["综合判断", "关键证据", "处置动作", "证据缺口", "误报与白名单"]

    def analyze(self, case_id: str, event: NormalizedEvent, memory: list[dict[str, Any]]) -> AgentResult:
        context = {
            "result_contract_version": "security-analysis-v2",
            "product": event.product,
            "severity": event.severity,
            "event_type": event.event_type,
            "entities": event.entities,
            "evidence": event.evidence,
            "memory": memory,
            "focus": self.analysis_focus(),
            "report_outline": self.report_outline(),
        }
        # Single choke point before any LLM call: deep-redact sensitive fields/
        # patterns and bound the context size so secrets never leave the process
        # and the model never receives an unbounded payload. The prompt is built
        # from this same sanitized context so truncation is consistent across the
        # prompt string and the context channel.
        context = self.policy.sanitize_context(context)
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
            + "\n输出契约对 local-rule-analyst、Ollama 和内网 LLM Gateway 完全一致：必须返回同一 JSON 字段集合，不能改字段名、不能把报告写到 JSON 外。"
            + "\nreason 必须是可直接给 SOC 分析师阅读的报告，第一行固定为“研判结论：<verdict>”，第二行固定为“分析报告：”。"
            + "\nanalysis_dimensions 必须按输入 report_outline 的小标题组织；每个维度只写结论化证据，不复写完整 payload。没有证据的维度也要说明缺口，而不是留空。"
            + "\nverdict 只能使用三类格式：【真实攻击】- 原因、【误报】- 原因、【需人工复核】- 原因。SIEM 真实事件也归入【真实攻击】标签。"
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
        verdict = explanation.get("verdict") or self._first_reason_line(llm_result.get("reason", ""))
        core_evidence = self._core_evidence_sentence(explanation.get("dimensions", []))
        impact_value = self._strip_terminal(impact) if impact else "当前证据不足以量化影响范围"
        impact_text = f"业务影响：{impact_value}。"
        return (
            f"{verdict}。{self.product.upper()} {event.event_type} 判定为 {classification}，置信度 {confidence:.2f}。"
            f"关键实体：{entity_bits}。核心依据：{self._strip_terminal(core_evidence)}。{impact_text}"
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
            return self._merge_with_structured(llm_result, structured, event)
        if llm_dims and llm_verdict and self._dimensions_support_classification(llm_dims, classification):
            return self._complete_result_shape(llm_result, event, classification)
        return self._reconcile_ungrounded(llm_result, event, explanation, classification)

    def _merge_with_structured(self, llm_result: dict[str, Any], structured: dict[str, Any], event: NormalizedEvent) -> dict[str, Any]:
        """Override the model's classification/verdict/dimensions with structured
        sample ground truth, keeping the model's free-text enrichments when they
        add value.

        When the model disagrees with the structured truth, the override is
        flagged (``ground_truth_override``) and noted in ``reason`` rather than
        applied silently — so a mislabeled sample cannot suppress a correct model
        verdict without leaving an auditable trace for the analyst.
        """
        merged = dict(llm_result)
        model_cls = self._normalize_classification(llm_result.get("classification", "insufficient_evidence"))
        structured_cls = self._normalize_classification(structured["classification"])
        if model_cls and model_cls != structured_cls:
            merged["_ground_truth_override"] = {
                "model_classification": model_cls,
                "structured_classification": structured_cls,
                "note": "样本结构化真值与模型结论冲突，已以真值为准并标记供人工复核。",
            }
            note = f"[证据锚定] 模型判定为「{model_cls}」，与样本结构化真值「{structured_cls}」不一致，已采用真值并标记供复核。"
            existing = str(merged.get("reason", "")).strip()
            merged["reason"] = (note + "\n" + existing) if existing else note
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
        # Pass the event so that, when the structured ground truth carries only
        # an expected_verdict (no analysis_dimensions), _complete_result_shape
        # synthesizes consistent dimensions from the evidence instead of leaving
        # the dashboard with zero evidence dimensions.
        return self._complete_result_shape(merged, event, structured["classification"])

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
        return self._complete_result_shape(merged, event, classification)

    def _complete_result_shape(
        self,
        llm_result: dict[str, Any],
        event: NormalizedEvent | None,
        classification: str,
    ) -> dict[str, Any]:
        """Fill optional-but-operational fields without changing the public
        JSON contract expected from future Gateway responses."""
        merged = dict(llm_result)
        merged["classification"] = self._normalize_classification(merged.get("classification", classification))
        merged["confidence"] = self._normalize_confidence(merged.get("confidence", 0.3))
        merged["verdict"] = self._format_verdict(str(merged.get("verdict") or ""), merged["classification"])
        dims = self._explanation(merged).get("dimensions", [])
        if not dims and event is not None:
            dims = self._synthesize_dimensions(event, merged["classification"])
        merged["analysis_dimensions"] = dims
        if not str(merged.get("reason", "")).strip():
            merged["reason"] = self._reason_from_dimensions(merged["verdict"], dims)
        if not isinstance(merged.get("recommended_next_steps"), list):
            merged["recommended_next_steps"] = []
        if not isinstance(merged.get("missing_evidence"), list):
            merged["missing_evidence"] = []
        if "business_impact" not in merged:
            merged["business_impact"] = ""
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
        """Quorum check: the model's dimensions must actually back its classification.

        A single supporting dimension among many ``info`` gaps is not enough (that
        is the common high-confidence-verdict-with-all-info-dims failure). Require
        either two or more supporting dimensions, or a single supporting dimension
        when it is the only dimension present.
        """
        valid = [d for d in dims if isinstance(d, dict)]
        if not valid:
            return False
        supporting = sum(
            1 for d in valid if self._status_supports_classification(d.get("status"), classification)
        )
        if supporting >= 2:
            return True
        return supporting >= 1 and len(valid) < 2

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
        for title in self.report_outline():
            evidence = self._evidence_for_report_title(title, event, by_type, entities, classification, label)
            if evidence:
                dims.append({"title": title, "status": self._status_for_report_title(title, classification, evidence), "evidence": evidence})

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

    def _evidence_for_report_title(
        self,
        title: str,
        event: NormalizedEvent,
        by_type: dict[str, Any],
        entities: dict[str, Any],
        classification: str,
        label: str,
    ) -> str:
        product = event.product.lower()
        text = title.lower()
        action = entities.get("action") or by_type.get("action")
        rule = entities.get("rule") or by_type.get("rule_id") or by_type.get("rule_name") or by_type.get("rule_info")
        if product == "rasp":
            if "参数" in title:
                return self._join_facts(
                    [
                        self._fact("方法", entities.get("method") or by_type.get("method")),
                        self._fact("路径/URL", entities.get("url") or by_type.get("url") or by_type.get("uri")),
                        self._fact("污染源", by_type.get("taint_source")),
                        self._fact("载荷摘要", by_type.get("payload_category")),
                    ],
                    "缺少请求参数、路径或污染源证据，无法完整判断入口特征。",
                )
            if "危险调用" in title:
                return self._join_facts(
                    [
                        self._fact("sink", by_type.get("sink")),
                        self._fact("stack", by_type.get("stack_trace") or by_type.get("stacktrace")),
                        self._fact("异常", by_type.get("exception")),
                    ],
                    "未提取到危险 sink 或调用栈，需要补充 RASP 原始 stacktrace。",
                )
            if "规则" in title:
                return f"命中规则 {self._short(rule)}，当前分类为「{label}」。" if rule else "缺少 rule_info/rule_id，无法校验规则与漏洞类型是否一致。"
            if "上下文" in title:
                return self._join_facts(
                    [
                        self._fact("hook_data", by_type.get("hook_data")),
                        self._fact("动作", action),
                        self._fact("应用", entities.get("app")),
                        self._fact("主机", entities.get("host")),
                        self._fact("来源", entities.get("src_ip")),
                    ],
                    "缺少 hook_data、动作或应用上下文，需回看原始 RASP 告警。",
                )
            if "成功" in title:
                if action:
                    blocked = "已阻断或拦截" if self._looks_blocked(action) else "未确认阻断"
                    return f"RASP 动作为 {self._short(action)}，{blocked}；仍需结合响应、异常和后续日志确认是否造成影响。"
                return "缺少 RASP 动作、响应或异常证据，无法判断攻击是否成功。"
            if "误报" in title or "白名单" in title:
                return "仅当确认业务合法且边界足够精确时才建议白名单；当前需限定规则、路径、参数、sink/stacktrace 和应用范围。"
        if product == "waf":
            if "请求" in title:
                return self._join_facts([self._fact("方法", entities.get("method") or by_type.get("method")), self._fact("URL", entities.get("url") or by_type.get("uri")), self._fact("来源", entities.get("src_ip"))], "缺少 URL、方法或来源上下文。")
            if "参数" in title or "header" in text:
                return self._join_facts([self._fact("命中字段", by_type.get("matched_parameters")), self._fact("载荷摘要", by_type.get("payload_category"))], "缺少命中参数/Header 或载荷摘要。")
            if "规则" in title:
                return f"命中规则 {self._short(rule)}，需核对规则描述、命中字段和攻击类型是否一致。" if rule else "缺少 WAF 规则字段。"
            if "响应" in title or "处置" in title:
                return self._join_facts([self._fact("动作", action), self._fact("状态码", by_type.get("status"))], "缺少 WAF 动作或响应码。")
            if "基线" in title:
                return self._join_facts([self._fact("频率", by_type.get("session_count_30m")), self._fact("窗口", by_type.get("rate_window")), self._fact("基线", by_type.get("baseline"))], "缺少同源、同账号或同 URI 频率基线。")
            if "关联" in title:
                return self._join_facts([self._fact("关联", by_type.get("correlation") or by_type.get("related_events"))], "缺少 RASP/NDR/SIEM 或应用日志关联证据。")
        if product == "hips":
            if "主机" in title or "身份" in title:
                return self._join_facts([self._fact("主机", entities.get("host")), self._fact("用户", entities.get("user")), self._fact("来源", entities.get("src_ip"))], "缺少主机、用户或登录来源。")
            if "进程链" in title:
                return self._join_facts([self._fact("进程", entities.get("process") or by_type.get("process_name")), self._fact("父进程", by_type.get("parent_process"))], "缺少父子进程证据。")
            if "命令行" in title or "脚本" in title:
                return self._join_facts([self._fact("命令行摘要", by_type.get("command_line"))], "缺少命令行或脚本摘要。")
            if "行为" in title:
                return self._join_facts([self._fact("近期上下文", by_type.get("recent_context")), self._fact("网络", by_type.get("dst_ip") or entities.get("dst_ip"))], "缺少文件、注册表、服务、网络等行为证据。")
            if "规则" in title or "处置" in title:
                return self._join_facts([self._fact("规则", rule), self._fact("动作", action)], "缺少 HIPS 规则或处置动作。")
            if "基线" in title or "变更" in title:
                return self._join_facts([self._fact("基线", by_type.get("baseline")), self._fact("近期上下文", by_type.get("recent_context"))], "缺少基线、变更单或历史误报证据。")
        if product == "ndr":
            if "通信" in title:
                return self._join_facts([self._fact("源", entities.get("src_ip") or entities.get("host")), self._fact("目的", entities.get("dst_ip") or by_type.get("sni")), self._fact("协议", by_type.get("protocol"))], "缺少源、目的或协议方向。")
            if "时序" in title or "流量" in title:
                return self._join_facts([self._fact("会话", by_type.get("session_count_30m")), self._fact("间隔", by_type.get("beacon_interval_seconds")), self._fact("出/入", self._bytes_pair(by_type))], "缺少会话频率、周期或流量比例。")
            if "协议" in title or "指纹" in title:
                return self._join_facts([self._fact("SNI", by_type.get("sni")), self._fact("JA3", by_type.get("ja3")), self._fact("JA4", by_type.get("ja4"))], "缺少 DNS/TLS/HTTP 指纹。")
            if "目的地" in title or "信誉" in title:
                return self._join_facts([self._fact("目的", entities.get("dst_ip")), self._fact("SNI", by_type.get("sni")), self._fact("基线", by_type.get("baseline"))], "缺少目的地信誉、ASN、地理位置或首次出现时间。")
            if "关联" in title:
                return self._join_facts([self._fact("关联", by_type.get("correlation") or by_type.get("related_events"))], "缺少主机、应用或 SIEM 关联证据。")
            if "数据" in title:
                return self._join_facts([self._fact("出站字节", by_type.get("bytes_out")), self._fact("入站字节", by_type.get("bytes_in"))], "缺少外传规模或横向移动结果证据。")
        if product == "siem":
            if "时间线" in title:
                return self._join_facts([self._fact("时间线", by_type.get("timeline"))], "缺少关键事件时间线。")
            if "实体" in title:
                return self._join_facts([self._fact("用户", entities.get("user")), self._fact("主机", entities.get("host")), self._fact("源", entities.get("src_ip")), self._fact("目的", entities.get("dst_ip"))], "缺少用户、主机、IP 或应用实体关系。")
            if "攻击链" in title:
                return self._join_facts([self._fact("摘要", by_type.get("case_summary")), self._fact("信号", by_type.get("signals"))], "缺少可映射到攻击阶段的多源信号。")
            if "多源" in title:
                return self._join_facts([self._fact("关联", by_type.get("correlation") or by_type.get("related_events")), self._fact("信号", by_type.get("signals"))], "缺少多源支持或冲突证据。")
            if "影响" in title:
                return self._join_facts([self._fact("业务影响", by_type.get("business_impact")), self._fact("实体", json.dumps(entities, ensure_ascii=False))], "缺少账号、主机、数据或监管影响证据。")
            if "缺口" in title:
                return self._join_facts([self._fact("缺口", by_type.get("missing_evidence"))], "需补充原始日志、时间线、实体关系和处置结果。")
            if "响应" in title:
                return "按当前严重级别和置信度确定升级优先级；只读验证优先，高影响动作需审批。"
        if "成功" in title or "危害" in title:
            # Generic success/impact handler for products without a dedicated branch
            # (WAF/HIPS/NDR/SIEM). Without this the "成功与危害" dimension promised
            # by report_outline was silently dropped.
            if action:
                blocked = "已阻断或拦截" if self._looks_blocked(action) else "未确认阻断"
                return f"产品动作为 {self._short(action)}，{blocked}；需结合响应、后续日志和资产影响确认是否造成实际危害。"
            return "缺少产品处置动作或响应结果，无法判断攻击是否成功及实际危害。"
        if "综合" in title or "关键" in title:
            indicators = self._collect_attack_indicators(event, by_type, entities)
            return indicators or f"基于 {len(event.evidence or [])} 条归一化证据，当前分类为「{label}」。"
        if "处置" in title:
            return f"安全产品动作：{self._short(action)}。" if action else "缺少产品处置动作。"
        if "缺口" in title:
            return "需补充原始日志、关联事件、资产画像和业务上下文。"
        return ""

    def _status_for_report_title(self, title: str, classification: str, evidence: str) -> str:
        if "缺少" in evidence or "无法" in evidence or "需补充" in evidence:
            return "review" if classification in {"malicious", "suspicious"} else "info"
        if "处置" in title or "响应" in title or "成功" in title:
            if "已阻断" in evidence or "blocked" in evidence.lower() or "拦截" in evidence:
                return "blocked"
        if "误报" in title or "白名单" in title or classification == "benign":
            return "benign" if classification == "benign" else "review"
        return self._CLASSIFICATION_STATUS.get(classification, "info")

    def _reason_from_dimensions(self, verdict: str, dims: list[dict[str, Any]]) -> str:
        lines = [f"研判结论：{verdict}", "分析报告："]
        for item in dims:
            lines.append(f"- {item.get('title') or '证据维度'}：{item.get('evidence') or '无补充说明'}")
        return "\n".join(lines)

    def _core_evidence_sentence(self, dims: list[dict[str, Any]]) -> str:
        selected = []
        for item in dims:
            status = self._normalize_dimension_status(item.get("status"))
            if status in {"risk", "blocked", "review", "benign", "normal"}:
                title = str(item.get("title") or "证据维度")
                evidence = self._strip_terminal(self._short(item.get("evidence") or ""))
                if evidence:
                    selected.append(f"{title}：{evidence}")
            if len(selected) >= 2:
                break
        return "；".join(selected) if selected else "当前仅有归一化证据，需结合原始日志复核"

    def _strip_terminal(self, value: Any) -> str:
        return strip_terminal(value)

    def _join_facts(self, facts: list[str], fallback: str) -> str:
        return join_facts(facts, fallback)

    def _fact(self, label: str, value: Any) -> str:
        return fact(label, value)

    def _bytes_pair(self, by_type: dict[str, Any]) -> str:
        if by_type.get("bytes_out") or by_type.get("bytes_in"):
            return f"{by_type.get('bytes_out', '-')}/{by_type.get('bytes_in', '-')}"
        return ""

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
        return short_text(value)

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
        "critical": "risk",
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
        if "真实攻击" in verdict or "真实事件" in verdict or classification == "malicious":
            tag = "【真实攻击】"
        elif "误报" in verdict or classification == "benign":
            tag = "【误报】"
        else:
            tag = "【需人工复核】"
        detail = verdict
        if detail:
            detail = re.sub(r"^【(?:真实攻击|真实事件|误报|需人工复核)】[\s\-:：、，,]*", "", detail).strip()
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
        explanation = {
            "verdict": verdict,
            "dimensions": normalized_dimensions,
            "whitelist_recommendation": whitelist,
            "raw_reason": reason,
        }
        if llm_result.get("_ground_truth_override"):
            explanation["ground_truth_override"] = llm_result["_ground_truth_override"]
        return explanation

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
        return normalize_classification(value)

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
