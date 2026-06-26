from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from .config import LLMConfig


class LLMClient:
    def analyze(self, prompt: str, context: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class LocalHeuristicLLM(LLMClient):
    """Deterministic local analyzer for offline MVP and tests."""

    HIGH_WORDS = ["rce", "sql", "xss", "c2", "exfil", "lateral", "credential", "webshell", "提权", "横向", "外传"]
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
        if severity in {"critical", "high"} or score >= 2:
            classification = "suspicious"
            confidence = min(0.92, 0.62 + score * 0.08)
        elif score == 1:
            classification = "suspicious"
            confidence = 0.58
        else:
            classification = "insufficient_evidence"
            confidence = 0.42
        return {
            "classification": classification,
            "confidence": confidence,
            "verdict": "【需人工复核】- 本地规则分析器缺少结构化证据维度",
            "analysis_dimensions": self._fallback_dimensions(context, score, severity),
            "reason": (
                "研判结论：【需人工复核】- 本地规则分析器缺少结构化证据维度\n"
                "分析报告：\n"
                f"- 严重级别：输入严重级别为 {severity}\n"
                f"- 关键词风险：命中 {score} 个高风险关键词\n"
                "- 证据缺口：生产环境应替换为企业 LLM Gateway 或提供 evidence_assessment 字段"
            ),
            "missing_evidence": ["缺少样本 evidence_assessment 或企业 LLM 深度研判结果"],
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
        return [
            {"title": "严重级别", "status": "info", "evidence": f"告警严重级别为 {severity}。"},
            {"title": "关键词风险", "status": "info", "evidence": f"上下文命中 {score} 个高风险关键词。"},
            {"title": "关键实体", "status": "info", "evidence": json.dumps(entities, ensure_ascii=False, sort_keys=True)},
            {"title": "证据密度", "status": "info", "evidence": f"归一化证据 {len(evidence) if isinstance(evidence, list) else 0} 条。"},
        ]

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
        payload = json.dumps({"model": self.config.model, "prompt": prompt, "context": context}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self.config.endpoint, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        api_key = self.config.api_key or os.getenv(self.config.api_key_env)
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            return json.loads(resp.read().decode("utf-8"))


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
                "temperature": 0.1,
                "top_p": 0.9,
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
