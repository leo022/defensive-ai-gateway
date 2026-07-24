from __future__ import annotations

import copy
import hashlib
from typing import Any

from .models import NormalizedEvent, RawAlert
from .policy import PolicyEngine


ENTITY_KEYS = {
    "host": ["host", "hostname", "server", "agent_host"],
    "user": ["user", "username", "account"],
    "src_ip": ["src_ip", "source_ip", "client_ip"],
    "dst_ip": ["dst_ip", "destination_ip", "server_ip"],
    "url": ["url", "uri", "path"],
    "process": ["process", "process_name", "image"],
    "rule": ["rule", "rule_id", "signature"],
    "app": ["app", "application", "service"],
    "method": ["method", "http_method"],
    "action": ["action", "hips_action", "rasp_action"],
}


# These fields are test/demo annotations, not security telemetry. Accepting them
# from ordinary HTTP or syslog alerts lets a sender inject a desired verdict or
# an unsafe whitelist. They are retained only when the server has marked the
# RawAlert as a trusted sample out of band.
_SAMPLE_CONTROL_FIELDS = {
    "trusted_sample",
    "_trusted_sample",
    "evidence_assessment",
    "expected_verdict",
    "analysis_dimension",
    "analysis_dimensions",
    "whitelist_candidate",
    "tuning_candidate",
}

_COMPOUND_EVIDENCE_FIELDS = {
    "hook_data",
    "request_parameters",
    "request_context",
    "rasp_items_context",
    "rasp_evidence_integrity",
    "collector_mapping_fallback",
}


class EventNormalizer:
    def __init__(self, policy: PolicyEngine):
        self.policy = policy

    def normalize(self, alert: RawAlert) -> NormalizedEvent:
        source_payload = (
            copy.deepcopy(alert.payload)
            if alert.trusted_sample
            else self._strip_sample_controls(alert.payload)
        )
        payload = self.policy.redact(source_payload)
        flat = self._flatten(payload)
        entities = self._extract_entities(flat)
        evidence = self._build_evidence(alert, payload, flat)
        tags = self._sensitivity_tags(alert.payload)
        return NormalizedEvent(
            # The source alert ID is the ingestion idempotency key. Making the
            # normalized-event ID deterministic lets a retry reuse immutable
            # evidence instead of creating a second analysis/case link.
            event_id=self._event_id(alert.alert_id),
            source=alert.source,
            product=alert.product.lower(),
            event_type=alert.event_type,
            severity=alert.severity.lower(),
            timestamp=alert.timestamp,
            entities=entities,
            evidence=evidence,
            sensitivity_tags=tags,
            raw_ref=alert.alert_id,
        )

    def _strip_sample_controls(self, value: Any) -> Any:
        """Deep-copy telemetry while removing untrusted analysis directives."""
        if isinstance(value, dict):
            return {
                key: self._strip_sample_controls(item)
                for key, item in value.items()
                if str(key).lower() not in _SAMPLE_CONTROL_FIELDS
            }
        if isinstance(value, list):
            return [self._strip_sample_controls(item) for item in value]
        return copy.deepcopy(value)

    @staticmethod
    def _event_id(alert_id: str) -> str:
        digest = hashlib.sha256(str(alert_id).encode("utf-8")).hexdigest()
        return f"event_{digest[:32]}"

    def _flatten(self, value: Any, prefix: str = "") -> dict[str, Any]:
        out: dict[str, Any] = {}
        if isinstance(value, dict):
            if prefix and prefix.lower().split(".")[-1] in _COMPOUND_EVIDENCE_FIELDS:
                out[prefix] = copy.deepcopy(value)
            for key, item in value.items():
                path = f"{prefix}.{key}" if prefix else key
                out.update(self._flatten(item, path))
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                path = f"{prefix}.{idx}" if prefix else str(idx)
                out.update(self._flatten(item, path))
        else:
            out[prefix] = value
        return out

    def _extract_entities(self, flat: dict[str, Any]) -> dict[str, Any]:
        entities: dict[str, Any] = {}
        lower_map = {key.lower().split(".")[-1]: value for key, value in flat.items()}
        for entity, keys in ENTITY_KEYS.items():
            for key in keys:
                if key in lower_map and lower_map[key] not in ("", None):
                    entities[entity] = lower_map[key]
                    break
        return entities

    def _build_evidence(self, alert: RawAlert, payload: dict[str, Any], flat: dict[str, Any]) -> list[dict[str, Any]]:
        evidence = [
            {
                "ref": alert.alert_id,
                "source": alert.product.lower(),
                "type": alert.event_type,
                "severity": alert.severity.lower(),
                "why_it_matters": "原始安全产品告警，经网关脱敏后进入分析。",
            }
        ]
        evidence.extend(self._structured_evidence(alert, payload))
        for key in [
            "rule_id",
            "rule_name",
            "rule_info",
            "signature",
            "process_name",
            "parent_process",
            "command_line",
            "uri",
            "url",
            "method",
            "action",
            "status",
            "src_ip",
            "dst_ip",
            "host",
            "user",
            "ja3",
            "ja4",
            "sni",
            "matched_parameters",
            "request_context",
            "request_parameters",
            "payload_category",
            "stacktrace",
            "stack_trace",
            "hook_data",
            "rasp_items_context",
            "rasp_evidence_integrity",
            "taint_source",
            "sink",
            "exception",
            "bytes_out",
            "bytes_in",
            "session_count_30m",
            "beacon_interval_seconds",
            "query",
            "case_summary",
            "collector_mapping_fallback",
        ]:
            if key in _COMPOUND_EVIDENCE_FIELDS and any(
                str(item.get("type") or "").lower() == key
                for item in evidence
                if isinstance(item, dict)
            ):
                continue
            for path, value in flat.items():
                if path.lower().endswith(key) and value:
                    evidence.append(
                        {
                            "ref": f"{alert.alert_id}:{path}",
                            "source": alert.product.lower(),
                            "type": key,
                            "value": value,
                            "why_it_matters": self._why_key_matters(key),
                        }
                    )
                    break
        for key, value in flat.items():
            leaf = key.lower().split(".")[-1]
            if leaf in {
                "payload",
                "body",
                "authorization",
                "cookie",
                "password",
                "token",
                "access_token",
                "refresh_token",
                "client_secret",
                "api_key",
                "x-api-key",
                "x_api_key",
            }:
                continue
            if len(evidence) >= 18:
                break
            if isinstance(value, (str, int, float, bool)) and value not in ("", None):
                evidence.append({"ref": f"{alert.alert_id}:{key}", "source": alert.product.lower(), "type": leaf, "value": value})
        return evidence[:18]

    def _structured_evidence(self, alert: RawAlert, payload: dict[str, Any]) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = []
        product = alert.product.lower()
        assessment = payload.get("evidence_assessment")
        if isinstance(assessment, dict):
            verdict = assessment.get("expected_verdict")
            if verdict:
                evidence.append(
                    {
                        "ref": f"{alert.alert_id}:evidence_assessment.expected_verdict",
                        "source": product,
                        "type": "expected_verdict",
                        "value": verdict,
                        "why_it_matters": "样本标注的期望研判结论，用于离线演示和 harness 可解释性校验。",
                    }
                )
            dimensions = assessment.get("analysis_dimensions")
            if isinstance(dimensions, list):
                for idx, item in enumerate(dimensions[:8]):
                    if not isinstance(item, dict):
                        continue
                    evidence.append(
                        {
                            "ref": f"{alert.alert_id}:evidence_assessment.analysis_dimensions.{idx}",
                            "source": product,
                            "type": "analysis_dimension",
                            "value": {
                                "title": item.get("title") or item.get("dimension"),
                                "status": item.get("status", "info"),
                                "evidence": item.get("evidence") or item.get("detail"),
                            },
                            "weight": item.get("status", "info"),
                            "why_it_matters": "提示词要求的分维度判断依据，可直接支撑 AI 解释。",
                        }
                    )
            for key in ["success_assessment", "business_impact", "missing_evidence"]:
                if assessment.get(key):
                    evidence.append(
                        {
                            "ref": f"{alert.alert_id}:evidence_assessment.{key}",
                            "source": product,
                            "type": key,
                            "value": assessment[key],
                            "why_it_matters": self._why_key_matters(key),
                        }
                    )
        whitelist = payload.get("whitelist_candidate") or payload.get("tuning_candidate")
        if isinstance(whitelist, dict):
            evidence.append(
                {
                    "ref": f"{alert.alert_id}:whitelist_candidate",
                    "source": product,
                    "type": "whitelist_candidate",
                    "value": whitelist,
                    "weight": "false_positive_only",
                    "why_it_matters": "仅在误报结论下使用的精确白名单或规则调优候选。",
                }
            )
        adapter_evidence = payload.get("adapter_evidence")
        if isinstance(adapter_evidence, list):
            for idx, item in enumerate(adapter_evidence[:12]):
                if not isinstance(item, dict):
                    continue
                item_type = str(item.get("type") or "mapped_field")
                if not alert.trusted_sample and item_type.lower() in _SAMPLE_CONTROL_FIELDS:
                    continue
                evidence.append(
                    {
                        "ref": item.get("ref") or f"{alert.alert_id}:adapter_evidence.{idx}",
                        "source": item.get("source") or product,
                        "type": item_type,
                        "value": item.get("value"),
                        "why_it_matters": item.get("why_it_matters") or "日志适配配置提取的证据字段。",
                    }
                )
        for key in ["attack_data", "correlation", "related_events", "timeline", "signals", "rate_window", "baseline", "recent_context"]:
            value = payload.get(key)
            if value:
                evidence.append(
                    {
                        "ref": f"{alert.alert_id}:{key}",
                        "source": product,
                        "type": key,
                        "value": value,
                        "why_it_matters": self._why_key_matters(key),
                    }
                )
        return evidence

    def _why_key_matters(self, key: str) -> str:
        return {
            "rule_id": "检测规则是判断规则有效性和调优边界的核心字段。",
            "rule_name": "规则描述帮助判断命中逻辑是否符合攻击类型。",
            "rule_info": "规则说明可用于对照漏洞或行为特征。",
            "process_name": "进程名用于分析主机行为和父子进程链。",
            "parent_process": "父进程可验证进程链是否符合正常业务或运维路径。",
            "command_line": "命令行是主机攻击意图和误报边界的重要证据。",
            "uri": "请求路径用于判断业务接口和 WAF/RASP 白名单范围。",
            "url": "URL 用于判断 Web 请求、重定向、SSRF 或外联目标。",
            "method": "HTTP 方法可辅助判断接口行为是否符合业务预期。",
            "action": "安全产品动作影响攻击是否成功和处置优先级。",
            "status": "响应码可辅助判断请求是否被阻断或到达应用。",
            "src_ip": "来源地址用于行为基线、溯源和范围限定。",
            "dst_ip": "目的地址用于网络方向、资产关系和外联风险判断。",
            "host": "主机名用于资产画像、影响面和历史基线关联。",
            "user": "账号用于判断身份上下文、权限和异常登录。",
            "ja3": "TLS 指纹可辅助判断异常客户端或 C2 行为。",
            "ja4": "TLS 指纹可辅助判断异常客户端或 C2 行为。",
            "sni": "SNI 可辅助判断外联目的地和业务合法性。",
            "matched_parameters": "命中参数用于判断 payload 位置和白名单粒度。",
            "request_parameters": "请求参数摘要用于判断入口特征；空对象表示上游未提供有效请求参数。",
            "request_context": "请求参数和请求体的受控语义摘要表明 RASP 是否已提供 HTTP 上下文；原始内容保留在原始告警中。",
            "payload_category": "载荷类别提供攻击特征摘要，同时避免泄露完整 payload。",
            "stacktrace": "调用栈用于验证 RASP hook 是否经过危险函数。",
            "stack_trace": "调用栈用于验证 RASP hook 是否经过危险函数。",
            "hook_data": "hook_data 是 RASP 判断攻击载荷与危险 sink 的关键上下文。",
            "rasp_items_context": "RASP items[] 的受控摘要保留每条规则、动作、hook_data 状态和危险 sink，避免仅分析第一条规则。",
            "rasp_evidence_integrity": "原始 RASP 日志指纹及请求/items 状态用于审计从收集到分析的证据连续性。",
            "taint_source": "污染源说明数据是否来自用户可控输入。",
            "sink": "危险 sink 用于确认攻击链是否触达敏感执行点。",
            "exception": "异常信息可辅助判断攻击是否被阻断或触发保护。",
            "bytes_out": "出站字节数用于判断外传风险。",
            "bytes_in": "入站字节数用于判断通信比例和会话行为。",
            "session_count_30m": "会话数用于判断频率异常和周期性。",
            "beacon_interval_seconds": "固定间隔是 C2 beacon 的重要行为特征。",
            "query": "查询串可辅助判断业务请求上下文。",
            "case_summary": "Case 摘要提供 SIEM 聚合判断背景。",
            "collector_mapping_fallback": "该事件因 Syslog Profile 映射不完整而被保留，需修正映射后复核原始日志。",
            "success_assessment": "成功性判断帮助区分已阻断攻击和已造成影响的事件。",
            "business_impact": "业务影响说明处置优先级和潜在损害。",
            "missing_evidence": "证据缺口指导下一步只读验证。",
            "attack_data": "RASP attack_data 汇总规则、hook_data 和调用栈。",
            "correlation": "多源关联可提升或降低单点告警置信度。",
            "related_events": "关联事件帮助判断攻击链是否连续。",
            "timeline": "时间线用于 SIEM 攻击链重建。",
            "signals": "多源信号用于 SIEM 融合判断和一致性校验。",
            "rate_window": "短时间频率可区分攻击、扫描和正常业务突增。",
            "baseline": "基线信息用于识别异常目的地或正常业务模式。",
            "recent_context": "近期上下文用于主机误报和异常行为判断。",
        }.get(key, "该字段为安全分析提供上下文证据。")

    def _sensitivity_tags(self, payload: dict[str, Any]) -> list[str]:
        tags: list[str] = []
        text = str(payload).lower()
        for needle, tag in [
            ("token", "credential"),
            ("access_token", "credential"),
            ("refresh_token", "credential"),
            ("client_secret", "credential"),
            ("api_key", "credential"),
            ("x-api-key", "credential"),
            ("password", "credential"),
            ("cookie", "credential"),
            ("authorization", "credential"),
            ("customer", "customer_data"),
            ("phone", "personal_data"),
            ("email", "personal_data"),
            ("id_card", "personal_data"),
        ]:
            if needle in text and tag not in tags:
                tags.append(tag)
        return tags
