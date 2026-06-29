from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from .config import LLMConfig
from .agents.evidence_helpers import fact, join_facts, normalize_classification, short_text


class LLMClient:
    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def is_deterministic(self) -> bool:
        """True for analyzers whose judgment is already grounded and need no
        reconciliation against structured sample evidence (e.g. the heuristic
        analyzer that reads ``evidence_assessment`` and merges memory itself)."""
        return False


class LocalHeuristicLLM(LLMClient):
    """Deterministic local analyzer for offline MVP and tests."""

    is_deterministic = True

    HIGH_WORDS = [
        "rce",
        "sql",
        "xss",
        "c2",
        "exfil",
        "lateral",
        "credential",
        "webshell",
        "jndi",
        "ldap://",
        "fastjson",
        "deserialization",
        "processbuilder",
        "提权",
        "横向",
        "外传",
        "反序列化",
        "命令执行",
    ]
    FALSE_POSITIVE_WORDS = [
        "false_positive",
        "false positive",
        "benign",
        "approved",
        "maintenance",
        "canary",
        "synthetic",
        "误报",
        "已批准",
        "巡检",
        "演练",
    ]

    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        text = json.dumps(context, ensure_ascii=False).lower()
        score = sum(1 for word in self.HIGH_WORDS if word in text)
        severity = context.get("severity", "medium").lower()
        sample_assessment = self._sample_assessment(context)
        memory_match = self._false_positive_memory_match(context)
        if sample_assessment:
            if memory_match:
                return self._merge_memory_match(sample_assessment, memory_match)
            return sample_assessment
        if memory_match:
            return {
                "classification": "benign",
                "confidence": memory_match["confidence"],
                "verdict": "【误报】- 命中已批准的长期误报记忆",
                "analysis_dimensions": [
                    {
                        "title": "历史误报",
                        "status": "benign",
                        "evidence": f"命中记忆 {memory_match['memory_id']}，匹配特征：{', '.join(memory_match['matched_features'])}",
                    },
                    {
                        "title": "复核边界",
                        "status": "review",
                        "evidence": "误报记忆只降低优先级，当前告警仍需核对频率、来源和影响面是否偏离历史基线。",
                    },
                ],
                "reason": (
                    "研判结论：【误报】- 命中已批准的长期误报记忆\n"
                    "分析报告：\n"
                    f"- 历史误报：命中记忆 {memory_match['memory_id']}，匹配特征：{', '.join(memory_match['matched_features'])}\n"
                    "- 复核边界：仍需确认当前告警未偏离已知模式\n"
                    "本地规则分析器命中已批准的长期误报记忆："
                    f"{memory_match['memory_id']}；匹配特征：{', '.join(memory_match['matched_features'])}。"
                    "建议仍保留只读复核，确认当前告警未偏离已知模式。"
                ),
                "recommended_next_steps": [
                    "核对当前告警的规则、应用、路径和来源是否仍符合已批准误报模式",
                    "若频率、来源或影响面偏离历史基线，升级 SOC 人工复核",
                ],
                "missing_evidence": ["误报记忆只降低优先级，不替代对新异常特征的复核"],
                "business_impact": "符合已批准误报模式时可降低告警噪声，但需防止攻击者伪装成已知模式。",
            }
        if self._strong_attack_signal(context, score, severity):
            classification = "malicious"
            confidence = min(0.92, 0.72 + score * 0.05)
        elif severity in {"critical", "high"} or score >= 2:
            classification = "suspicious"
            confidence = min(0.9, 0.62 + score * 0.08)
        elif score == 1:
            classification = "suspicious"
            confidence = 0.58
        else:
            classification = "insufficient_evidence"
            confidence = 0.42
        return {
            "classification": classification,
            "confidence": confidence,
            "verdict": self._verdict_from_classification(classification),
            "analysis_dimensions": self._fallback_dimensions(context, score, severity),
            "reason": self._fallback_reason(context, classification, score, severity),
            "recommended_next_steps": self._fallback_next_steps(context, classification),
            "missing_evidence": ["缺少样本 evidence_assessment 或企业 LLM 深度研判结果"],
            "business_impact": self._fallback_business_impact(context, classification),
        }

    def _merge_memory_match(self, result: dict[str, Any], memory_match: dict[str, Any]) -> dict[str, Any]:
        merged = dict(result)
        original_classification = str(merged.get("classification", "insufficient_evidence"))
        verdict = str(merged.get("verdict") or self._verdict_from_classification(original_classification))
        if original_classification == "benign":
            merged["verdict"] = f"{verdict}；命中已批准误报记忆"
        elif original_classification == "suspicious" and memory_match["confidence"] >= 0.78:
            merged["classification"] = "benign"
            merged["verdict"] = f"【误报】- 当前可疑告警与已批准误报记忆高度相似，建议按误报优先复核"
        elif original_classification == "malicious":
            merged["verdict"] = f"{verdict}；注意存在相似误报历史但当前仍按真实攻击处理"
        else:
            merged["verdict"] = f"{verdict}；命中相似误报记忆，误报可能性上升"
        dimensions = list(merged.get("analysis_dimensions") or [])
        dimensions.append(
            {
                "title": "历史误报",
                "status": "benign" if merged.get("classification") == "benign" else "review",
                "evidence": (
                    f"命中已批准的长期误报记忆 {memory_match['memory_id']}；"
                    f"相似度 {memory_match['similarity']:.2f}；"
                    f"匹配特征：{', '.join(memory_match['matched_features'])}。"
                ),
            }
        )
        merged["analysis_dimensions"] = dimensions
        base_confidence = float(merged.get("confidence", 0.0) or 0.0)
        if merged.get("classification") == "benign":
            merged["confidence"] = round(min(0.9, max(base_confidence, memory_match["confidence"]) + 0.02), 2)
        else:
            merged["confidence"] = round(max(base_confidence, min(0.82, memory_match["confidence"])), 2)
        merged["reason"] = (
            str(merged.get("reason") or "")
            + "\n- 历史误报："
            + f"命中已批准的长期误报记忆 {memory_match['memory_id']}；相似度 {memory_match['similarity']:.2f}；匹配特征：{', '.join(memory_match['matched_features'])}。"
        ).strip()
        steps = list(merged.get("recommended_next_steps") or [])
        steps.append("核对当前告警的规则、资产、路径、客户端和频率是否仍符合已批准误报记忆")
        if original_classification == "malicious":
            steps.append("当前样本仍有攻击证据，不应仅凭相似误报历史自动降级")
        merged["recommended_next_steps"] = steps
        return merged

    def _sample_assessment(self, context: dict[str, Any]) -> dict[str, Any] | None:
        evidence = context.get("evidence") or []
        if not isinstance(evidence, list):
            return None
        expected_verdict = ""
        dimensions: list[dict[str, Any]] = []
        whitelist: dict[str, Any] = {}
        success = ""
        impact = ""
        missing: list[str] = []
        for item in evidence:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            value = item.get("value")
            if item_type == "expected_verdict" and value:
                expected_verdict = str(value)
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
            elif item_type == "success_assessment" and value:
                success = str(value)
            elif item_type == "business_impact" and value:
                impact = str(value)
            elif item_type == "missing_evidence":
                if isinstance(value, list):
                    missing.extend(str(part) for part in value if part)
                elif value:
                    missing.append(str(value))
        if not expected_verdict and not dimensions:
            return None
        classification = self._classification_from_verdict(expected_verdict, context)
        confidence = self._confidence_from_assessment(classification, dimensions, context)
        verdict = expected_verdict or self._verdict_from_classification(classification)
        reason = self._reason_from_assessment(verdict, dimensions, success, impact, whitelist)
        next_steps = self._next_steps_from_assessment(classification, whitelist, missing)
        return {
            "classification": classification,
            "confidence": confidence,
            "verdict": verdict,
            "analysis_dimensions": dimensions,
            "reason": reason,
            "recommended_next_steps": next_steps,
            "missing_evidence": missing,
            "business_impact": impact,
            "whitelist_recommendation": whitelist,
        }

    def _classification_from_verdict(self, verdict: str, context: dict[str, Any]) -> str:
        text = verdict.lower()
        if "误报" in text or "benign" in text:
            return "benign"
        if "真实" in text or "真实攻击" in text or "真实事件" in text or "malicious" in text:
            return "malicious"
        if "需人工复核" in text or "可疑" in text or "suspicious" in text:
            return "suspicious"
        severity = str(context.get("severity", "")).lower()
        return "suspicious" if severity in {"critical", "high"} else "insufficient_evidence"

    def _confidence_from_assessment(self, classification: str, dimensions: list[dict[str, Any]], context: dict[str, Any]) -> float:
        status_text = " ".join(str(item.get("status", "")) for item in dimensions).lower()
        support = len([item for item in dimensions if str(item.get("evidence", "")).strip()])
        confidence = 0.62 + min(0.18, support * 0.025)
        if classification == "benign":
            confidence += 0.08 if any(word in status_text for word in ["benign", "normal", "allow"]) else 0.02
        if classification == "malicious":
            confidence += 0.08 if any(word in status_text for word in ["risk", "malicious", "blocked"]) else 0.04
        if str(context.get("severity", "")).lower() in {"critical", "high"}:
            confidence += 0.04
        return round(max(0.35, min(0.94, confidence)), 2)

    def _verdict_from_classification(self, classification: str) -> str:
        return {
            "malicious": "【真实攻击】- 样本证据指向攻击行为",
            "suspicious": "【需人工复核】- 样本证据支持可疑但缺少关键确认",
            "benign": "【误报】- 样本证据指向合法业务或已知误报",
        }.get(classification, "【需人工复核】- 证据不足")

    def _reason_from_assessment(
        self,
        verdict: str,
        dimensions: list[dict[str, Any]],
        success: str,
        impact: str,
        whitelist: dict[str, Any],
    ) -> str:
        lines = [f"研判结论：{verdict}", "分析报告："]
        for item in dimensions:
            title = str(item.get("title") or "证据维度")
            evidence = str(item.get("evidence") or "无补充说明")
            lines.append(f"- {title}：{evidence}")
        if success:
            lines.append(f"- 成功与危害：{success}")
        if impact:
            lines.append(f"- 业务影响：{impact}")
        if whitelist:
            lines.append(f"- 误报与白名单：{self._format_whitelist(whitelist)}")
        return "\n".join(lines)

    def _next_steps_from_assessment(
        self,
        classification: str,
        whitelist: dict[str, Any],
        missing: list[str],
    ) -> list[str]:
        steps = []
        if classification == "benign" and whitelist:
            steps.append("建议添加以下白名单：" + self._format_whitelist(whitelist))
        if missing:
            steps.append("补充证据：" + "；".join(missing[:4]))
        if classification in {"malicious", "suspicious"}:
            steps.append("基于当前证据进行只读复核，确认产品动作、业务影响和是否存在后续关联告警")
        if not steps:
            steps.append("复核样本证据维度是否与当前告警完全一致")
        return steps

    def _format_whitelist(self, whitelist: dict[str, Any]) -> str:
        order = [
            "rule_type",
            "attack_type",
            "detection_content",
            "match_method",
            "scope",
            "reason",
            "review_cycle",
        ]
        parts = []
        for key in order:
            value = whitelist.get(key)
            if value:
                parts.append(f"{key}=`{value}`")
        for key, value in whitelist.items():
            if key not in order and value:
                parts.append(f"{key}=`{value}`")
        return "；".join(parts)

    def _fallback_dimensions(self, context: dict[str, Any], score: int, severity: str) -> list[dict[str, str]]:
        entities = context.get("entities") or {}
        evidence = context.get("evidence") or []
        classification = "malicious" if self._strong_attack_signal(context, score, severity) else ("suspicious" if severity in {"critical", "high"} or score else "insufficient_evidence")
        status = {
            "malicious": "risk",
            "suspicious": "review",
            "benign": "benign",
        }.get(classification, "info")
        by_type = self._evidence_by_type(evidence)
        outline = context.get("report_outline") or ["综合判断", "关键证据", "处置动作", "证据缺口", "误报与白名单"]
        dims = []
        for title in outline:
            detail = self._fallback_dimension_detail(str(context.get("product", "")), str(title), entities, by_type, score, severity)
            dims.append({"title": str(title), "status": self._fallback_dimension_status(str(title), detail, status), "evidence": detail})
        return dims

    def _fallback_reason(self, context: dict[str, Any], classification: str, score: int, severity: str) -> str:
        verdict = self._verdict_from_classification(classification)
        lines = [f"研判结论：{verdict}", "分析报告："]
        for item in self._fallback_dimensions(context, score, severity):
            lines.append(f"- {item['title']}：{item['evidence']}")
        return "\n".join(lines)

    def _fallback_next_steps(self, context: dict[str, Any], classification: str) -> list[str]:
        product = str(context.get("product") or "security").upper()
        steps = [
            f"只读复核 {product} 原始告警，确认规则、关键实体、处置动作和时间窗口",
            "关联同一资产、同一来源、同一账号在前后 30 分钟内的相关告警",
        ]
        if classification in {"suspicious", "malicious"}:
            steps.append("补充产品原始日志或接入内网 LLM Gateway 后重新生成深度研判")
        else:
            steps.append("若确认业务合法，再评估最小范围白名单或规则调优")
        return steps

    def _fallback_business_impact(self, context: dict[str, Any], classification: str) -> str:
        entities = context.get("entities") or {}
        asset = entities.get("app") or entities.get("host") or entities.get("url") or entities.get("src_ip") or "相关资产"
        if classification == "suspicious":
            return f"{asset} 存在可疑安全信号，当前证据不足以确认影响范围；需优先补齐原始日志和关联证据。"
        if classification == "malicious":
            return f"{asset} 可能受到真实攻击影响，需要确认是否已被阻断以及是否存在后续横向、外联或数据风险。"
        return f"{asset} 暂未形成明确攻击证据，主要风险是告警噪声或证据不足导致的误判。"

    def _strong_attack_signal(self, context: dict[str, Any], score: int, severity: str) -> bool:
        product = str(context.get("product") or "").lower()
        evidence = context.get("evidence") or []
        by_type = self._evidence_by_type(evidence)
        if product == "rasp":
            has_runtime_path = bool(by_type.get("sink") or by_type.get("stack_trace") or by_type.get("stacktrace"))
            has_attack_context = bool(by_type.get("hook_data") or by_type.get("taint_source") or by_type.get("payload_category"))
            if has_runtime_path and (has_attack_context or score >= 2):
                return True
        if product == "waf":
            action = str((context.get("entities") or {}).get("action") or by_type.get("action") or "").lower()
            return severity in {"critical", "high"} and score >= 2 and any(word in action for word in ["block", "阻断"])
        if product in {"hips", "ndr", "siem"}:
            return severity in {"critical", "high"} and score >= 2
        return severity == "critical" and score >= 3

    def _evidence_by_type(self, evidence: Any) -> dict[str, Any]:
        by_type: dict[str, Any] = {}
        if not isinstance(evidence, list):
            return by_type
        for item in evidence:
            if isinstance(item, dict) and item.get("type") and item.get("type") not in by_type:
                by_type[str(item["type"])] = item.get("value")
        return by_type

    def _fallback_dimension_detail(
        self,
        product: str,
        title: str,
        entities: dict[str, Any],
        by_type: dict[str, Any],
        score: int,
        severity: str,
    ) -> str:
        product = product.lower()
        if product == "rasp":
            if "参数" in title:
                return self._join_facts(
                    [
                        self._fact("方法", entities.get("method") or by_type.get("method")),
                        self._fact("URL", entities.get("url") or by_type.get("url") or by_type.get("uri")),
                        self._fact("污染源", by_type.get("taint_source")),
                        self._fact("载荷摘要", by_type.get("payload_category")),
                    ],
                    "缺少参数、路径或污染源明细，无法完整判断入口特征。",
                )
            if "危险调用" in title:
                return self._join_facts(
                    [
                        self._fact("sink", by_type.get("sink")),
                        self._fact("stack", by_type.get("stack_trace") or by_type.get("stacktrace")),
                    ],
                    "缺少危险 sink 或调用栈，需要回看 RASP 原始 stacktrace。",
                )
            if "规则" in title:
                return self._join_facts([self._fact("规则", entities.get("rule") or by_type.get("rule_id") or by_type.get("rule_name"))], "缺少 RASP 规则信息。")
            if "上下文" in title:
                return self._join_facts([self._fact("hook_data", by_type.get("hook_data")), self._fact("动作", entities.get("action") or by_type.get("action")), self._fact("应用", entities.get("app")), self._fact("主机", entities.get("host"))], "缺少 hook_data、动作或应用上下文。")
            if "成功" in title:
                action = entities.get("action") or by_type.get("action")
                return f"产品动作为 {self._short(action)}；需要结合响应、异常和后续日志确认是否成功。" if action else "缺少动作、响应或异常证据，无法判断成功性。"
            if "误报" in title:
                return "如判定误报，白名单必须限定规则、路径/参数、应用、sink 或 stacktrace，避免宽泛放行。"
        if product == "waf":
            if "请求" in title:
                return self._join_facts([self._fact("方法", entities.get("method") or by_type.get("method")), self._fact("URL", entities.get("url") or by_type.get("uri")), self._fact("来源", entities.get("src_ip"))], "缺少 URL、方法或来源。")
            if "参数" in title:
                return self._join_facts([self._fact("命中字段", by_type.get("matched_parameters")), self._fact("载荷摘要", by_type.get("payload_category"))], "缺少命中参数/Header 或载荷摘要。")
            if "规则" in title:
                return self._join_facts([self._fact("规则", entities.get("rule") or by_type.get("rule_id") or by_type.get("rule_name"))], "缺少 WAF 规则信息。")
            if "响应" in title:
                return self._join_facts([self._fact("动作", entities.get("action") or by_type.get("action")), self._fact("状态码", by_type.get("status"))], "缺少 WAF 动作或响应码。")
        if product == "hips":
            if "主机" in title:
                return self._join_facts([self._fact("主机", entities.get("host")), self._fact("用户", entities.get("user")), self._fact("来源", entities.get("src_ip"))], "缺少主机、用户或登录来源。")
            if "进程链" in title:
                return self._join_facts([self._fact("进程", entities.get("process") or by_type.get("process_name")), self._fact("父进程", by_type.get("parent_process"))], "缺少父子进程证据。")
            if "命令行" in title:
                return self._join_facts([self._fact("命令行摘要", by_type.get("command_line"))], "缺少命令行或脚本摘要。")
            if "规则" in title:
                return self._join_facts([self._fact("规则", entities.get("rule") or by_type.get("rule_id")), self._fact("动作", entities.get("action") or by_type.get("action"))], "缺少 HIPS 规则或动作。")
        if product == "ndr":
            if "通信" in title:
                return self._join_facts([self._fact("源", entities.get("src_ip") or entities.get("host")), self._fact("目的", entities.get("dst_ip") or by_type.get("sni")), self._fact("协议", by_type.get("protocol"))], "缺少源、目的或协议方向。")
            if "时序" in title or "流量" in title:
                return self._join_facts([self._fact("会话", by_type.get("session_count_30m")), self._fact("间隔", by_type.get("beacon_interval_seconds")), self._fact("出站字节", by_type.get("bytes_out"))], "缺少时序或流量证据。")
            if "协议" in title or "指纹" in title:
                return self._join_facts([self._fact("SNI", by_type.get("sni")), self._fact("JA3", by_type.get("ja3")), self._fact("JA4", by_type.get("ja4"))], "缺少 DNS/TLS/HTTP 指纹。")
        if product == "siem":
            if "时间线" in title:
                return self._join_facts([self._fact("时间线", by_type.get("timeline"))], "缺少关键事件时间线。")
            if "实体" in title:
                return self._join_facts([self._fact("用户", entities.get("user")), self._fact("主机", entities.get("host")), self._fact("源", entities.get("src_ip"))], "缺少实体关系。")
            if "攻击链" in title:
                return self._join_facts([self._fact("摘要", by_type.get("case_summary")), self._fact("信号", by_type.get("signals"))], "缺少多源攻击链信号。")
        if "误报" in title or "白名单" in title:
            return "仅在业务合法、边界明确且有复核周期时建议白名单或规则调优。"
        if "成功" in title or "危害" in title or "影响" in title or "数据" in title:
            return "需要结合产品动作、后续日志和业务资产画像判断成功性与影响范围。"
        if "关联" in title or "多源" in title:
            return "缺少跨产品关联证据，需要补充 HIPS/RASP/NDR/WAF/SIEM 或应用日志。"
        if "缺口" in title or "响应" in title:
            return "当前为本地规则分析器输出，需补充原始日志、上下文和 Gateway 深度研判。"
        return f"严重级别为 {severity}，上下文命中 {score} 个高风险关键词，关键实体为 {json.dumps(entities, ensure_ascii=False, sort_keys=True)}。"

    def _fallback_dimension_status(self, title: str, detail: str, default: str) -> str:
        if "缺少" in detail or "无法" in detail or "需要" in detail:
            return "review"
        if "动作" in title or "响应" in title or "成功" in title:
            if any(word in detail.lower() for word in ["block", "blocked", "阻断", "拦截"]):
                return "blocked"
        if "误报" in title or "白名单" in title:
            return "review"
        return default

    def _join_facts(self, facts: list[str], fallback: str) -> str:
        return join_facts(facts, fallback)

    def _fact(self, label: str, value: Any) -> str:
        return fact(label, value)

    def _short(self, value: Any) -> str:
        return short_text(value)

    def _false_positive_memory_match(self, context: dict[str, Any]) -> dict[str, Any] | None:
        memories = (context.get("memory") or {}).get("product_long_term", [])
        if not isinstance(memories, list):
            return None
        alert_text = json.dumps(
            {
                "product": context.get("product"),
                "event_type": context.get("event_type"),
                "entities": context.get("entities"),
                "evidence": context.get("evidence"),
            },
            ensure_ascii=False,
            sort_keys=True,
        ).lower()
        alert_features = self._extract_memory_features(alert_text)
        best: dict[str, Any] | None = None
        for memory in memories:
            if not isinstance(memory, dict):
                continue
            if memory.get("status") != "active":
                continue
            if str(memory.get("trust_level", "low")).lower() == "low":
                continue
            memory_text = json.dumps(memory, ensure_ascii=False, sort_keys=True).lower()
            if not any(word in memory_text for word in self.FALSE_POSITIVE_WORDS):
                continue
            features = self._extract_memory_features(memory_text)
            matched = sorted(feature for feature in features if feature and (feature in alert_text or feature in alert_features))
            if not matched:
                retrieval_key = str(memory.get("retrieval_key", "")).strip().lower()
                if retrieval_key and retrieval_key in alert_text:
                    matched = [retrieval_key]
            if not matched:
                continue
            similarity = len(set(matched)) / max(3, min(len(features), len(alert_features)) or 3)
            if len(matched) < 2 and similarity < 0.55:
                continue
            confidence = min(0.88, 0.62 + 0.18 * similarity + 0.03 * min(len(matched), 4))
            candidate = {
                "memory_id": memory.get("memory_id", "unknown"),
                "matched_features": matched[:6],
                "confidence": confidence,
                "similarity": similarity,
            }
            if best is None or candidate["confidence"] > best["confidence"]:
                best = candidate
        return best

    def _extract_memory_features(self, memory_text: str) -> set[str]:
        features: set[str] = set()
        for pattern in [
            r"\b(?:waf|hips|rasp|ndr|siem)-[a-z0-9-]+",
            r"/[a-z0-9_./{}-]+",
            r"\b[a-z0-9_-]+(?:-api|-web|-gateway|-service|-client)(?:/[0-9.]+)?\b",
            r"\b[a-z0-9_-]+(?:-srv|-prod|-[0-9]{2})(?:/[0-9.]+)?\b",
            r"\b[a-z0-9_.-]+\.(?:internal|example)\b",
            r"\bsynthetic-browser\b",
            r"\bbank-partner-batch-client/[0-9.]+\b",
            r"\bbackup-vault\.internal\b",
            r"\bsynthetic-canary\b",
            r"\bsvc-patch\b",
            r"\bsvc-maintenance\b",
        ]:
            features.update(re.findall(pattern, memory_text, flags=re.IGNORECASE))
        normalized = {feature.strip().lower().rstrip(".,;:") for feature in features}
        return {feature for feature in normalized if len(feature) >= 4}


class GatewayLLM(LLMClient):
    """Generic JSON-over-HTTP adapter for enterprise LLM gateways."""

    def __init__(self, config: LLMConfig):
        self.config = config

    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        if not self.config.endpoint:
            raise RuntimeError("LLM endpoint is not configured")
        # ``context`` is already redacted + size-bounded by SecurityAgent.analyze
        # before reaching here, so we forward it verbatim to the gateway.
        payload = json.dumps({"model": self.config.model, "prompt": prompt, "context": context}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self.config.endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        api_key = self.config.api_key or os.getenv(self.config.api_key_env)
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                if resp.status >= 400:
                    raise RuntimeError(f"LLM gateway returned HTTP {resp.status}")
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"LLM gateway HTTP {exc.code}: {exc.read().decode('utf-8', errors='ignore')[:200]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM gateway unreachable: {exc.reason}") from exc
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"LLM gateway returned non-JSON response: {body[:200]}") from exc
        return _validate_result_shape(parsed, self.config.model)


def _validate_result_shape(parsed: Any, model: str) -> dict[str, Any]:
    """Ensure an LLM result conforms to the analysis contract.

    The enterprise gateway is the least-constrained backend (no grammar
    enforcement like Ollama's ``format``), so we validate the response here and
    fall back to a safe ``insufficient_evidence`` shell on any mismatch rather
    than letting a malformed dict propagate to reconciliation.
    """
    if not isinstance(parsed, dict):
        return {
            "classification": "insufficient_evidence",
            "confidence": 0.2,
            "reason": "LLM 网关返回非对象 JSON，已降级为证据不足。",
            "model": model,
        }
    parsed = dict(parsed)
    # Normalize Chinese classification labels (e.g. "真实攻击"/"误报") to the
    # canonical enum before the allow-list check, so a compliant-in-spirit but
    # Chinese-labeled gateway response is not downgraded to insufficient_evidence.
    original = str(parsed.get("classification", "")).strip().lower()
    normalized = normalize_classification(original)
    parsed["classification"] = normalized
    if normalized == "insufficient_evidence" and original and original not in {
        "malicious", "suspicious", "benign", "insufficient_evidence", "insufficient",
    }:
        # Unknown classification text: downgrade and explain.
        if "confidence" not in parsed:
            parsed["confidence"] = 0.2
        parsed.setdefault("reason", "LLM 网关返回的 classification 不合规，已降级为证据不足。")
    parsed.setdefault("model", model)
    return parsed


# JSON Schema for Ollama structured outputs. Mirrors the result contract that
# SecurityAgent._build_prompt asks for, so local models are grammar-constrained
# into the exact fields instead of free-form (or wrong-schema) JSON.
OLLAMA_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "classification": {
            "type": "string",
            "enum": ["malicious", "suspicious", "benign", "insufficient_evidence"],
        },
        "confidence": {"type": "number"},
        "verdict": {"type": "string"},
        "reason": {"type": "string"},
        "analysis_dimensions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["risk", "benign", "normal", "blocked", "review", "info"],
                    },
                    "evidence": {"type": "string"},
                },
                "required": ["title", "status", "evidence"],
            },
        },
        "whitelist_recommendation": {
            "type": "object",
            "properties": {
                "rule_type": {"type": "string"},
                "detection_content": {"type": "string"},
                "match_method": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
        "recommended_next_steps": {"type": "array", "items": {"type": "string"}},
        "missing_evidence": {"type": "array", "items": {"type": "string"}},
        "attack_stage": {"type": "array", "items": {"type": "string"}},
        "business_impact": {"type": "string"},
    },
    "required": [
        "classification",
        "confidence",
        "verdict",
        "reason",
        "analysis_dimensions",
        "business_impact",
        "missing_evidence",
        "recommended_next_steps",
    ],
}


class OllamaLLM(LLMClient):
    """Adapter for local Ollama models such as gemma3:4b."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self.endpoint = config.endpoint or "http://127.0.0.1:11434/api/generate"

    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        model = self.config.model or "gemma3:4b"
        try:
            return self._generate(model, prompt)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            if exc.code == 404 and model == "gemma3:4b":
                result = self._generate("gemma3:latest", prompt)
                result["model_fallback"] = "gemma3:4b not found; used gemma3:latest"
                return result
            raise RuntimeError(f"Ollama HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            # Connection refused / DNS / timeout — surface as a RuntimeError so the
            # orchestrator can degrade to the deterministic heuristic rather than
            # abort the whole alert.
            raise RuntimeError(f"Ollama unreachable: {exc.reason}") from exc

    def _generate(self, model: str, prompt: str) -> dict[str, Any]:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            # 结构化输出：用 JSON Schema 约束模型必须产出 Agent 约定的字段。
            # 仅靠 format:"json" 时，reasoning 模型（如 deepseek-r1）的 <think> 被
            # 语法约束抑制，容易原样回吐输入字段或产出错误 schema；显式 schema 可
            # 强制字段名与枚举值，显著提升本地小模型的字段遵循率。
            "format": OLLAMA_ANALYSIS_SCHEMA,
            "options": {
                # temperature 0 + fixed seed for reproducible harness replay; a
                # failing sample should fail consistently rather than pass on retry.
                "temperature": 0,
                "top_p": 0.9,
                "seed": 0,
            },
        }
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        response = str(data.get("response", "")).strip()
        parsed = _parse_json_object(response)
        parsed.setdefault("reason", "Ollama 本地模型完成分析。")
        parsed.setdefault("model", model)
        return parsed


def _parse_json_object(text: str) -> dict[str, Any]:
    if not text:
        return {"classification": "insufficient_evidence", "confidence": 0.2, "reason": "模型返回为空。"}
    # Reasoning models (e.g. deepseek-r1) may wrap chain-of-thought in
    # <think>...</think>; strip it so we parse only the final answer.
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
    return {
        "classification": "insufficient_evidence",
        "confidence": 0.25,
        "reason": f"模型未返回合法 JSON，原始摘要：{text[:500]}",
    }


def build_llm(config: LLMConfig) -> LLMClient:
    if config.provider == "local":
        return LocalHeuristicLLM()
    if config.provider == "ollama":
        return OllamaLLM(config)
    return GatewayLLM(config)
