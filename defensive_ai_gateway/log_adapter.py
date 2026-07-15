from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .models import RawAlert, now_ms
from .normalizer import EventNormalizer


SUPPORTED_PRODUCTS = {"hips", "rasp", "ndr", "waf", "siem"}
PRODUCT_LABELS = {"hips": "HIPS", "rasp": "RASP", "ndr": "NDR", "waf": "WAF", "siem": "SIEM"}
DEFAULT_REQUIRED_FIELDS = ["alert_id", "product", "event_type", "severity", "timestamp"]

# product → 默认自动套用的 mapping profile_id。仅对“无显式 product 字段、靠内容
# 指纹识别到的厂商原生日志”生效（显式带 product 的标准告警走快速路径，不会触发）。
# 新增产品接入并保存对应 profile 后，在此注册。与 deploy/k3s/syslog-collector-vector.yaml
# 中 classify_source 的 product→gateway_profile 映射保持同源。
AUTO_PROFILE: dict[str, str] = {
    product: f"auto-{product}-json" for product in SUPPORTED_PRODUCTS
}


def explicit_product(payload: dict[str, Any]) -> str | None:
    """Return the product if the payload carries an explicit, supported product field."""
    raw = payload.get("product")
    if raw is None:
        event = payload.get("event")
        if isinstance(event, dict):
            raw = event.get("product")
    product = str(raw or "").strip().lower()
    return product if product in SUPPORTED_PRODUCTS else None


def fingerprint_product(payload: dict[str, Any]) -> str | None:
    """Infer product from content fingerprints when no explicit product field exists.

    Kept in sync with the Vector ``classify_source`` remap in
    ``deploy/k3s/syslog-collector-vector.yaml`` so the HTTP path and the syslog
    path agree on vendor-log identification.
    """
    for path in (("device", "type"), ("source", "product"), ("event", "product")):
        node: Any = payload
        for part in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(part)
        product = str(node or "").strip().lower()
        if product in SUPPORTED_PRODUCTS:
            return product
    if str(payload.get("data_type")) == "attack_event" and (
        isinstance(payload.get("items"), list) or isinstance(payload.get("event"), dict)
    ):
        return "rasp"
    return None

DEFAULT_REQUIRED_FIELD_HINTS = {
    "alert_id": "映射到日志中的唯一告警 ID，例如 $.metadata.id、$.alert.id、$.alert_id 或 $.id。",
    "product": "映射到产品类型；若原始日志缺少该字段，可使用对应产品 literal。",
    "event_type": "映射到规则名称、攻击类型或事件类型，例如 $.rule.name、$.attack.type 或 $.event.type。",
    "severity": "映射到严重级别，例如 $.risk.level、$.severity 或 $.level。",
    "timestamp": "映射到事件时间，例如 $.time、$.timestamp 或 $.@timestamp。",
}
OPTIONAL_FIELD_HINTS = {
    "host": "主机名可提升资产画像、影响面判断和历史基线关联质量。",
    "stack_trace": "调用栈可提升 RASP 危险调用判断质量。",
    "sink": "危险 sink 可帮助确认攻击链是否触达敏感函数。",
    "hook_data": "hook_data 可帮助判断用户输入和危险 sink 的关系。",
    "taint_source": "污染源可帮助判断数据是否来自用户可控输入。",
    "trace_id": "trace_id 可帮助关联同一请求链路。",
    "request_id": "request_id 可帮助关联 WAF、应用访问日志和审计日志。",
}
INFER_FIELD_SPECS = [
    {
        "target": "alert_id",
        "label": "告警 ID",
        "required": True,
        "candidates": ["alert_id", "id", "event_id", "request_id", "alert.id", "metadata.id", "event.id", "event.request_id", "trace.id"],
    },
    {
        "target": "product",
        "label": "产品类型",
        "required": True,
        "candidates": ["product", "device.type", "source.product", "event.product"],
    },
    {
        "target": "event_type",
        "label": "事件类型",
        "required": True,
        "candidates": [
            "event_type",
            "rule.name",
            "rule_name",
            "attack.type",
            "attack_type",
            "items[0].attack_type",
            "items[0].rule_name",
            "event.type",
            "vulnerability.type",
            "type",
            "name",
        ],
    },
    {
        "target": "severity",
        "label": "严重级别",
        "required": True,
        "candidates": ["severity", "risk.level", "risk.severity", "level", "attack_level", "items[0].attack_level", "priority"],
    },
    {
        "target": "timestamp",
        "label": "事件时间",
        "required": True,
        "candidates": ["timestamp", "time", "@timestamp", "event.time", "event_time", "attack_time", "event.attack_time", "created_at"],
    },
    {
        "target": "entities.host",
        "label": "主机",
        "optional_key": "host",
        "candidates": ["host.name", "host.hostname", "hostname", "server_hostname", "event.server_hostname", "host", "runtime.host", "server.hostname"],
    },
    {
        "target": "entities.src_ip",
        "label": "源 IP",
        "optional_key": "src_ip",
        "candidates": ["src_ip", "source_ip", "client_ip", "attack_source", "event.attack_source", "http.client_ip", "request.client_ip", "client.ip", "source.ip"],
    },
    {
        "target": "entities.url",
        "label": "URL",
        "optional_key": "url",
        "candidates": ["url", "uri", "path", "event.path", "request_message.url", "event.request_message.url", "http.uri", "request.uri", "request.url"],
    },
    {
        "target": "entities.method",
        "label": "HTTP 方法",
        "optional_key": "method",
        "candidates": ["method", "request_message.method", "event.request_message.method", "http.method", "request.method"],
    },
    {
        "target": "entities.rule",
        "label": "规则 ID",
        "optional_key": "rule",
        "candidates": ["rule_id", "items[0].rule_id", "rule.id", "rule.rule_id", "attack.rule_id", "signature"],
    },
    {
        "target": "entities.app",
        "label": "应用",
        "optional_key": "app",
        "candidates": ["app", "app_name", "event.app_name", "app.name", "application.name", "service.name", "service"],
    },
    {
        "target": "entities.action",
        "label": "处置动作",
        "optional_key": "action",
        "candidates": ["action", "intercept_state", "items[0].intercept_state", "rasp.action", "attack.action", "rasp_action"],
    },
    {
        "target": "payload.event_time",
        "label": "Payload 时间",
        "optional_key": "event_time",
        "candidates": ["timestamp", "time", "@timestamp", "event.time", "event_time", "attack_time", "event.attack_time"],
    },
    {
        "target": "payload.host",
        "label": "Payload 主机",
        "optional_key": "host",
        "candidates": ["host.name", "host.hostname", "hostname", "server_hostname", "event.server_hostname", "host", "runtime.host", "server.hostname"],
    },
    {
        "target": "payload.stack_trace",
        "label": "调用栈",
        "optional_key": "stack_trace",
        "candidates": ["stacktrace", "items[0].stacktrace", "stack_trace", "exception.stacktrace", "attack.stacktrace"],
    },
    {
        "target": "payload.sink",
        "label": "危险 sink",
        "optional_key": "sink",
        "candidates": ["sink", "attack.sink"],
    },
    {
        "target": "payload.hook_data",
        "label": "Hook 数据",
        "optional_key": "hook_data",
        "candidates": ["hook_data", "items[0].hook_data", "attack.hook_data"],
    },
    {
        "target": "payload.taint_source",
        "label": "污染源",
        "optional_key": "taint_source",
        "candidates": ["taint_source", "taint.source", "attack.taint_source"],
    },
    {
        "target": "payload.trace_id",
        "label": "Trace ID",
        "optional_key": "trace_id",
        "candidates": ["trace_id", "trace.id", "request.trace_id"],
    },
    {
        "target": "payload.request_id",
        "label": "Request ID",
        "optional_key": "request_id",
        "candidates": ["request_id", "event.request_id", "request.id", "http.request_id"],
    },
]
RASP_ONLY_INFER_TARGETS = {
    "payload.stack_trace",
    "payload.sink",
    "payload.hook_data",
    "payload.taint_source",
}
DEFAULT_SEVERITY_MAP = {
    "critical": "critical",
    "严重": "critical",
    "高危": "critical",
    "1": "critical",
    "high": "high",
    "高": "high",
    "2": "high",
    "medium": "medium",
    "中": "medium",
    "中危": "medium",
    "3": "medium",
    "low": "low",
    "低": "low",
    "4": "low",
    "5": "low",
    "info": "low",
    "informational": "low",
}


@dataclass
class MappingProfile:
    profile_id: str
    name: str
    version: str
    description: str = ""
    enabled: bool = True
    mappings: dict[str, Any] = field(default_factory=dict)
    severity_map: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SEVERITY_MAP))
    product_map: dict[str, str] = field(default_factory=dict)
    event_type_map: dict[str, str] = field(default_factory=dict)
    required_fields: list[str] = field(default_factory=lambda: list(DEFAULT_REQUIRED_FIELDS))
    evidence_fields: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MappingProfile":
        return cls(
            profile_id=str(data.get("profile_id") or data.get("id") or "").strip(),
            name=str(data.get("name") or data.get("profile_id") or "").strip(),
            version=str(data.get("version") or "v1").strip(),
            description=str(data.get("description") or ""),
            enabled=bool(data.get("enabled", True)),
            mappings=dict(data.get("mappings") or {}),
            severity_map={**DEFAULT_SEVERITY_MAP, **dict(data.get("severity_map") or {})},
            product_map=dict(data.get("product_map") or {}),
            event_type_map=dict(data.get("event_type_map") or {}),
            required_fields=list(data.get("required_fields") or DEFAULT_REQUIRED_FIELDS),
            evidence_fields=list(data.get("evidence_fields") or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled,
            "mappings": self.mappings,
            "severity_map": self.severity_map,
            "product_map": self.product_map,
            "event_type_map": self.event_type_map,
            "required_fields": self.required_fields,
            "evidence_fields": self.evidence_fields,
        }


def default_mapping_profile() -> MappingProfile:
    return MappingProfile(
        profile_id="sample-standard",
        name="Sample 标准告警格式",
        version="v1",
        description="兼容 samples/*.json 与当前 /api/alerts 标准字段。",
        mappings={
            "alert_id": "$.alert_id",
            "source": "$.source",
            "product": "$.product",
            "event_type": "$.event_type",
            "severity": "$.severity",
            "timestamp": "$.timestamp",
            "payload": "$.payload",
        },
        evidence_fields=[],
    )


def demo_rasp_profile() -> MappingProfile:
    return MappingProfile(
        profile_id="demo-rasp-json",
        name="Demo RASP JSON 日志",
        version="v1",
        description="示例：把常见 RASP JSON 日志映射为内部 RawAlert，并保留 host、time、stacktrace、hook 和 trace 关键上下文。",
        mappings={
            "alert_id": ["$.metadata.id", "$.alert.id", "$.event.id", "$.event.request_id", "$.request_id", "$.id", "$.trace.id"],
            "source": ["$.device.vendor", "$.event.app_name", "$.event.agent_id", "$.agent.name", "$.source", {"literal": "rasp"}],
            "product": ["$.product", "$.device.type", {"literal": "rasp"}],
            "event_type": ["$.rule.name", "$.items[0].rule_name", "$.items[0].attack_type", "$.attack.type", "$.event.type", "$.vulnerability.type"],
            "severity": ["$.risk.level", "$.severity", "$.items[0].attack_level", "$.level", "$.risk.severity"],
            "timestamp": ["$.time", "$.timestamp", "$.@timestamp", "$.event.attack_time", "$.event.time", "$.event.created_at"],
            "entities.host": ["$.host.name", "$.host.hostname", "$.event.server_hostname", "$.host", "$.runtime.host", "$.server.hostname"],
            "entities.src_ip": ["$.event.attack_source", "$.http.client_ip", "$.request.client_ip", "$.client.ip", "$.source.ip"],
            "entities.url": ["$.event.request_message.url", "$.event.path", "$.http.uri", "$.request.uri", "$.request.url", "$.url"],
            "entities.method": ["$.event.request_message.method", "$.http.method", "$.request.method"],
            "entities.rule": ["$.rule.id", "$.items[0].rule_id", "$.rule.rule_id", "$.attack.rule_id"],
            "entities.app": ["$.event.app_name", "$.app.name", "$.application.name", "$.service.name"],
            "entities.action": ["$.rasp.action", "$.items[0].intercept_state", "$.action", "$.attack.action"],
            "payload.host": ["$.host.name", "$.host.hostname", "$.event.server_hostname", "$.host", "$.runtime.host", "$.server.hostname"],
            "payload.event_time": ["$.time", "$.timestamp", "$.@timestamp", "$.event.attack_time", "$.event.time"],
            "payload.stack_trace": ["$.stacktrace", "$.items[0].stacktrace", "$.stack_trace", "$.exception.stacktrace", "$.attack.stacktrace"],
            "payload.trace_id": ["$.trace.id", "$.trace_id", "$.request.trace_id"],
            "payload.request_id": ["$.event.request_id", "$.http.request_id", "$.request.id", "$.request_id"],
            "payload.hook_data": ["$.hook_data", "$.items[0].hook_data", "$.attack.hook_data"],
            "payload.taint_source": ["$.taint.source", "$.attack.taint_source"],
            "payload.sink": ["$.sink", "$.attack.sink", {"path": "$.items[0].stacktrace", "transform": "rasp_sink_from_stacktrace"}],
            "payload.exception": ["$.exception.message", "$.exception", "$.attack.exception"],
        },
        product_map={"runtime_app_protection": "rasp", "runtime_application_self_protection": "rasp", "rasp": "rasp"},
        evidence_fields=[
            {"type": "rule_id", "path": "$.rule.id", "why_it_matters": "RASP 规则 ID 用于关联误报记忆和调优范围。"},
            {"type": "rule_id", "path": "$.items[0].rule_id", "why_it_matters": "RASP 规则 ID 用于关联误报记忆和调优范围。"},
            {"type": "stack_trace", "path": "$.stacktrace", "why_it_matters": "调用栈用于确认用户输入是否触达危险 sink。"},
            {"type": "stack_trace", "path": "$.items[0].stacktrace", "why_it_matters": "调用栈用于确认用户输入是否触达危险 sink。"},
            {"type": "sink", "path": "$.sink", "why_it_matters": "危险 sink 是判断 RASP 告警成功性和影响面的核心字段。"},
            {"type": "sink", "path": {"path": "$.items[0].stacktrace", "transform": "rasp_sink_from_stacktrace"}, "why_it_matters": "真实 RASP 日志常把危险调用放在 stacktrace 顶部，可据此推导 sink。"},
            {"type": "action", "path": "$.rasp.action", "why_it_matters": "RASP 处置动作影响攻击是否已被阻断。"},
            {"type": "action", "path": "$.items[0].intercept_state", "why_it_matters": "RASP 处置动作影响攻击是否已被阻断。"},
        ],
    )


def builtin_product_profile(product: str) -> MappingProfile:
    """Return the reserved, multi-path JSON profile for one supported product."""
    product = str(product).strip().lower()
    if product not in SUPPORTED_PRODUCTS:
        raise ValueError(f"unsupported product: {product}")
    profile_id = f"auto-{product}-json"
    name = f"Built-in {PRODUCT_LABELS[product]} JSON 日志"
    description = f"内置 {PRODUCT_LABELS[product]} 多路径映射；覆盖标准字段、常见厂商嵌套字段和 Syslog envelope。"

    if product == "rasp":
        profile = demo_rasp_profile()
        profile.profile_id = profile_id
        profile.name = name
        profile.version = "v2"
        profile.description = description
        profile.mappings["product"] = [
            "$.product",
            "$.device.type",
            "$.source.product",
            "$.event.product",
            {"literal": product},
        ]
        return profile

    # Non-RASP profiles intentionally start from a product-neutral mapping.
    # Cloning the RASP template used to leak its ``source=rasp`` fallback,
    # stacktrace/sink extraction, and RASP aliases into WAF/NDR/HIPS/SIEM data.
    mappings: dict[str, Any] = {
        "alert_id": [
            "$.alert_id",
            "$.metadata.id",
            "$.alert.id",
            "$.event.id",
            "$.request_id",
            "$.id",
            "$.trace.id",
        ],
        "source": [
            "$.device.vendor",
            "$.source.vendor",
            "$.vendor",
            "$.agent.name",
            "$.source.name",
            "$._syslog_envelope.hostname",
            {"literal": product},
        ],
        "product": [
            "$.product",
            "$.device.type",
            "$.source.product",
            "$.event.product",
            {"literal": product},
        ],
        "event_type": [
            "$.event_type",
            "$.alert.category",
            "$.rule.name",
            "$.event.type",
            "$.type",
            "$.name",
        ],
        "severity": [
            "$.risk.level",
            "$.severity",
            "$.level",
            "$.risk.severity",
            "$.priority",
        ],
        "timestamp": [
            "$.timestamp",
            "$.time",
            "$.@timestamp",
            "$.event.time",
            "$.event_time",
            "$.event.created_at",
            "$._syslog_envelope.received_at",
        ],
        "entities.host": [
            "$.host.name",
            "$.host.hostname",
            "$.device.name",
            "$.hostname",
            "$._syslog_envelope.hostname",
        ],
        "entities.user": ["$.source.user", "$.user.name", "$.username", "$.user"],
        "entities.src_ip": ["$.source.ip", "$.http.client_ip", "$.request.client_ip", "$.client.ip", "$.src_ip"],
        "entities.dst_ip": ["$.destination.ip", "$.dst.ip", "$.server.ip", "$.dst_ip"],
        "entities.url": ["$.http.uri", "$.request.uri", "$.request.url", "$.url", "$.event.path"],
        "entities.method": ["$.http.method", "$.request.method", "$.method"],
        "entities.rule": ["$.rule.id", "$.rule.rule_id", "$.signature.id", "$.rule_id"],
        "entities.app": ["$.application.name", "$.app.name", "$.service.name", "$.app"],
        "entities.process": ["$.process.name", "$.process.image", "$.process_name"],
        "entities.action": ["$.action", "$.event.action", "$.disposition"],
    }
    product_aliases = {
        "waf": {"waf": "waf", "web_application_firewall": "waf"},
        "hips": {"hips": "hips", "host_intrusion_prevention": "hips"},
        "ndr": {"ndr": "ndr", "network_detection_response": "ndr"},
        "siem": {"siem": "siem", "security_information_event_management": "siem"},
    }
    common_evidence = [
        {"type": "rule_id", "path": "$.rule.id", "why_it_matters": "规则 ID 用于关联历史处置与误报边界。"},
        {"type": "action", "path": "$.action", "why_it_matters": "产品动作影响攻击是否已被阻断。"},
    ]
    product_evidence = {
        "waf": [
            {"type": "matched_parameters", "path": "$.matched_parameters", "why_it_matters": "命中参数用于界定 Web 攻击面和误报范围。"},
            {"type": "payload_category", "path": "$.payload_category", "why_it_matters": "载荷类别用于确认 Web 攻击特征。"},
        ],
        "hips": [
            {"type": "command_line", "path": "$.process.command_line", "why_it_matters": "命令行用于判断主机行为是否恶意。"},
            {"type": "behavior", "path": "$.behavior", "why_it_matters": "行为链用于判断主机攻击阶段和影响。"},
        ],
        "ndr": [
            {"type": "sni", "path": "$.destination.sni", "why_it_matters": "目的域名用于关联信誉和基线。"},
            {"type": "ja3", "path": "$.network.ja3", "why_it_matters": "TLS 指纹用于识别稀有通信行为。"},
            {"type": "bytes_out", "path": "$.network.bytes_out", "why_it_matters": "出站字节量用于判断外传风险。"},
        ],
        "siem": [
            {"type": "signals", "path": "$.signals", "why_it_matters": "关联信号用于验证跨产品攻击链。"},
            {"type": "correlation_logic", "path": "$.correlation_logic", "why_it_matters": "关联逻辑用于审计 SIEM Case 的形成依据。"},
        ],
    }
    return MappingProfile(
        profile_id=profile_id,
        name=name,
        version="v3",
        description=description,
        mappings=mappings,
        product_map=product_aliases[product],
        evidence_fields=[*common_evidence, *product_evidence[product]],
    )


class LogAdapter:
    def __init__(self, normalizer: EventNormalizer | None = None):
        self.normalizer = normalizer

    def adapt(self, profile: MappingProfile, log: dict[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        warnings: list[str] = []
        mapped: dict[str, Any] = {}
        entities: dict[str, Any] = {}
        payload_fields: dict[str, Any] = {}

        for target, source in profile.mappings.items():
            value = self._resolve_mapping(source, log)
            if value in ("", None):
                continue
            if target.startswith("entities."):
                entities[target.split(".", 1)[1]] = value
            elif target.startswith("payload."):
                self._assign_nested(payload_fields, target.split(".", 1)[1], value)
            else:
                mapped[target] = value

        if "payload" not in mapped:
            mapped["payload"] = log
        elif not isinstance(mapped["payload"], dict):
            warnings.append("payload 映射结果不是对象，已将原始日志作为 payload.original_log 保存。")
            mapped["payload"] = {"mapped_payload": mapped["payload"], "original_log": log}

        mapped["source"] = str(mapped.get("source") or profile.name or profile.profile_id or "mapped-log")
        mapped["product"] = self._map_value(mapped.get("product"), profile.product_map).lower()
        mapped["severity"] = self._map_value(mapped.get("severity"), profile.severity_map).lower()
        mapped["event_type"] = self._map_value(mapped.get("event_type"), profile.event_type_map)

        for required_field in profile.required_fields:
            if required_field not in mapped or mapped.get(required_field) in ("", None):
                errors.append(f"missing_required_field:{required_field}")

        if mapped.get("product") and mapped["product"] not in SUPPORTED_PRODUCTS:
            errors.append(f"unsupported_product:{mapped['product']}")

        if mapped.get("severity") and mapped["severity"] not in {"critical", "high", "medium", "low"}:
            errors.append(f"unsupported_severity:{mapped['severity']}")

        payload = dict(mapped.get("payload") or {})
        self._merge_dict(payload, payload_fields)
        payload.setdefault("original_log", log)
        payload["adapter"] = {
            "profile_id": profile.profile_id,
            "profile_name": profile.name,
            "profile_version": profile.version,
            "mapping_status": "passed" if not errors else "failed",
            "missing_required_fields": [item.split(":", 1)[1] for item in errors if item.startswith("missing_required_field:")],
            "warnings": warnings,
        }
        if entities:
            payload["mapped_entities"] = entities
            payload.update({key: value for key, value in entities.items() if key not in payload})

        adapter_evidence = self._build_adapter_evidence(profile, log)
        if adapter_evidence:
            payload["adapter_evidence"] = adapter_evidence

        raw_alert = None
        if not errors:
            raw_alert = RawAlert(
                source=str(mapped["source"]),
                product=str(mapped["product"]),
                event_type=str(mapped["event_type"]),
                severity=str(mapped["severity"]),
                timestamp=str(mapped["timestamp"]),
                payload=payload,
                alert_id=str(mapped["alert_id"]),
            )

        result = {
            "ok": not errors,
            "errors": errors,
            "warnings": warnings,
            "profile": {
                "profile_id": profile.profile_id,
                "name": profile.name,
                "version": profile.version,
                "enabled": profile.enabled,
            },
            "mapped_fields": {k: v for k, v in mapped.items() if k != "payload"},
            "mapped_entities": entities,
            "mapped_payload_fields": payload_fields,
            "adapter_evidence": adapter_evidence,
            "missing_required_fields": [item.split(":", 1)[1] for item in errors if item.startswith("missing_required_field:")],
            "field_mapping_hints": self._field_mapping_hints(profile, errors),
            "raw_alert": raw_alert,
            "raw_alert_preview": self._raw_alert_preview(raw_alert, mapped, payload),
        }
        if raw_alert and self.normalizer:
            event = self.normalizer.normalize(raw_alert)
            result["normalized_event_preview"] = {
                "event_id": event.event_id,
                "source": event.source,
                "product": event.product,
                "event_type": event.event_type,
                "severity": event.severity,
                "timestamp": event.timestamp,
                "entities": event.entities,
                "evidence": event.evidence,
                "sensitivity_tags": event.sensitivity_tags,
                "raw_ref": event.raw_ref,
            }
        return result

    def dry_run(self, profile: MappingProfile, log: dict[str, Any]) -> dict[str, Any]:
        result = self.adapt(profile, log)
        result.pop("raw_alert", None)
        return result

    def infer_mapping_profile(self, log: dict[str, Any], profile_id: str = "auto-rasp-json", product: str = "rasp") -> dict[str, Any]:
        flat = self._flatten_paths(log)
        fields: list[dict[str, Any]] = []
        product = product if product in SUPPORTED_PRODUCTS else "rasp"
        mappings: dict[str, Any] = {"source": {"literal": product}}
        product_label = PRODUCT_LABELS.get(product, product.upper())

        product_signal = self._product_signal(log, flat, product)
        for spec in INFER_FIELD_SPECS:
            target = str(spec["target"])
            if product != "rasp" and target in RASP_ONLY_INFER_TARGETS:
                continue
            candidates_for_product = list(spec["candidates"])
            if product != "rasp":
                candidates_for_product = [
                    candidate
                    for candidate in candidates_for_product
                    if "items[0]" not in candidate and not candidate.startswith("rasp.")
                ]
            match = self._best_path_match(flat, candidates_for_product)
            mapping: Any = match["path"] if match else None
            status = "missing"
            confidence = 0.0
            sample_value = None
            candidates = self._candidate_options(flat, candidates_for_product)

            if target == "product" and product_signal and (not match or product_signal["confidence"] >= match["confidence"]):
                mapping = {"literal": product_signal["product"]}
                status = "needs_review" if product_signal["confidence"] < 0.9 else "mapped"
                confidence = product_signal["confidence"]
                sample_value = product_signal["product"]
                candidates.insert(
                    0,
                    {
                        "path": f"__literal:{product_signal['product']}",
                        "value": product_signal["product"],
                        "confidence": product_signal["confidence"],
                    },
                )
            elif match:
                status = "mapped" if match["confidence"] >= 0.82 else "needs_review"
                confidence = match["confidence"]
                sample_value = match["value"]

            if target == "payload.sink" and mapping is None:
                stack_mapping = mappings.get("payload.stack_trace")
                stack_path = self._first_mapping_path(stack_mapping)
                stack_value = self._resolve_mapping(stack_mapping, log) if stack_mapping else None
                derived_sink = self._derive_rasp_sink(stack_value)
                if stack_path and derived_sink:
                    mapping = {"path": stack_path, "transform": "rasp_sink_from_stacktrace"}
                    status = "needs_review"
                    confidence = 0.78
                    sample_value = derived_sink
                    candidates.insert(0, {"path": stack_path, "value": derived_sink, "confidence": confidence, "transform": "rasp_sink_from_stacktrace"})

            if mapping is not None:
                mappings[target] = mapping

            optional_key = spec.get("optional_key") or target
            fields.append(
                {
                    "target": target,
                    "label": spec["label"],
                    "required": bool(spec.get("required", False)),
                    "optional_key": optional_key,
                    "mapping": mapping,
                    "path": self._mapping_label(mapping),
                    "sample_value": sample_value,
                    "confidence": round(confidence, 2),
                    "status": status,
                    "hint": DEFAULT_REQUIRED_FIELD_HINTS.get(target) if spec.get("required") else OPTIONAL_FIELD_HINTS.get(str(optional_key), ""),
                    "candidates": candidates[:8],
                }
            )

        profile = MappingProfile(
            profile_id=profile_id,
            name=f"Auto {product_label} JSON 日志",
            version="v1",
            description=f"由一条 {product_label} JSON 日志自动识别生成；可保存为正式 Mapping Profile。",
            mappings=mappings,
            product_map=(
                {
                    "rasp": "rasp",
                    "runtime_app_protection": "rasp",
                    "runtime_application_self_protection": "rasp",
                }
                if product == "rasp"
                else {product: product, product_label.lower(): product}
            ),
            evidence_fields=[
                {"type": "rule_id", "path": self._first_mapping_path(mappings.get("entities.rule")), "why_it_matters": f"{product_label} 规则 ID 用于关联误报记忆和调优范围。"},
                *(
                    [
                        {"type": "stack_trace", "path": self._first_mapping_path(mappings.get("payload.stack_trace")), "why_it_matters": "调用栈用于确认用户输入是否触达危险 sink。"},
                        {"type": "sink", "path": mappings.get("payload.sink"), "why_it_matters": "危险 sink 是判断应用侧告警成功性和影响面的核心字段。"},
                    ]
                    if product == "rasp"
                    else []
                ),
                {"type": "action", "path": self._first_mapping_path(mappings.get("entities.action")), "why_it_matters": f"{product_label} 处置动作影响攻击是否已被阻断。"},
            ],
        )
        profile.evidence_fields = [item for item in profile.evidence_fields if item.get("path")]
        required_missing = [field["target"] for field in fields if field["required"] and not field["mapping"]]
        recommended_keys = {"host", "trace_id", "request_id"}
        if product == "rasp":
            recommended_keys.update({"stack_trace", "sink"})
        recommended_missing = [
            field["optional_key"]
            for field in fields
            if field.get("optional_key") in recommended_keys and not field["mapping"]
        ]
        return {
            "ok": not required_missing,
            "profile": profile.to_dict(),
            "fields": fields,
            "required_missing": required_missing,
            "recommended_missing": recommended_missing,
            "quality": {
                "status": "passed" if not required_missing else "needs_mapping",
                "required_missing": required_missing,
                "recommended_missing": recommended_missing,
                "message": "必填字段已识别，可运行 dry-run。" if not required_missing else "请补齐必填字段后再运行 dry-run。",
            },
        }

    def _resolve_mapping(self, mapping: Any, log: dict[str, Any]) -> Any:
        if isinstance(mapping, list):
            for item in mapping:
                value = self._resolve_mapping(item, log)
                if value not in ("", None):
                    return value
            return None
        if isinstance(mapping, dict):
            if "literal" in mapping:
                return mapping["literal"]
            if "path" in mapping:
                value = self._path_get(log, str(mapping["path"]))
                return self._apply_transform(value, str(mapping.get("transform") or ""))
            return None
        if isinstance(mapping, str):
            if mapping.startswith("$.") or mapping == "$":
                return self._path_get(log, mapping)
            return mapping
        return mapping

    def _flatten_paths(self, value: Any, prefix: str = "$") -> dict[str, Any]:
        out: dict[str, Any] = {}
        if isinstance(value, dict):
            if prefix != "$" and prefix.lower().split(".")[-1] in {"hook_data", "request_message", "response_message"}:
                out[prefix] = value
            for key, item in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                out.update(self._flatten_paths(item, path))
        elif isinstance(value, list):
            if prefix != "$":
                out[prefix] = value
            for idx, item in enumerate(value):
                path = f"{prefix}[{idx}]"
                out.update(self._flatten_paths(item, path))
        else:
            out[prefix] = value
        return out

    def _best_path_match(self, flat: dict[str, Any], candidates: list[str]) -> dict[str, Any] | None:
        options = self._candidate_options(flat, candidates)
        return options[0] if options else None

    def _candidate_options(self, flat: dict[str, Any], candidates: list[str]) -> list[dict[str, Any]]:
        scored: list[dict[str, Any]] = []
        wanted = [item.lower().lstrip("$.") for item in candidates]
        generic_leafs = {"id", "name", "type", "level", "source"}
        for path, value in flat.items():
            if value in ("", None):
                continue
            clean = path.lower().lstrip("$.")
            leaf = clean.split(".")[-1]
            score = 0.0
            for candidate in wanted:
                candidate_leaf = candidate.split(".")[-1]
                if clean == candidate:
                    score = max(score, 0.98)
                elif clean.endswith("." + candidate):
                    score = max(score, 0.9)
                elif leaf == candidate_leaf and candidate_leaf not in generic_leafs:
                    score = max(score, 0.74)
                elif candidate_leaf not in generic_leafs and (candidate_leaf in leaf or leaf in candidate_leaf):
                    score = max(score, 0.55)
            if score:
                scored.append({"path": path, "value": value, "confidence": score})
        scored.sort(key=lambda item: (-float(item["confidence"]), len(str(item["path"]))))
        return scored

    def _product_signal(self, log: dict[str, Any], flat: dict[str, Any], fallback_product: str = "rasp") -> dict[str, Any] | None:
        text = json.dumps(log, ensure_ascii=False).lower()
        product_match = self._best_path_match(flat, ["product", "device.type", "source.product", "event.product"])
        if product_match:
            value = str(product_match["value"]).lower()
            for product in SUPPORTED_PRODUCTS:
                if product in value:
                    return {"product": product, "confidence": 0.98}

        fingerprints = {
            "rasp": ["rasp", "stacktrace", "stack_trace", "hook_data", "taint", "sink"],
            "waf": ["waf", "xff", "http", "uri", "matched_parameters", "web_attack"],
            "hips": ["hips", "powershell", "process", "command_line", "file_hash", "parent_process"],
            "ndr": ["ndr", "ja3", "bytes_out", "bytes_in", "dst_ip", "beacon"],
            "siem": ["siem", "correlation", "timeline", "offense", "case"],
        }
        scores = {
            product: sum(1 for needle in needles if needle in text)
            for product, needles in fingerprints.items()
        }
        best_product, best_score = max(scores.items(), key=lambda item: item[1])
        if best_score >= 2:
            return {"product": best_product, "confidence": 0.88}
        if best_score == 1:
            return {"product": best_product, "confidence": 0.72}
        return {"product": fallback_product if fallback_product in SUPPORTED_PRODUCTS else "rasp", "confidence": 0.62}

    def _mapping_label(self, mapping: Any) -> str:
        if isinstance(mapping, dict) and "literal" in mapping:
            return f"literal:{mapping['literal']}"
        if isinstance(mapping, dict) and mapping.get("transform"):
            return f"{mapping.get('path')} | {mapping.get('transform')}"
        return str(mapping or "")

    def _first_mapping_path(self, mapping: Any) -> str:
        if isinstance(mapping, str):
            return mapping
        if isinstance(mapping, list):
            for item in mapping:
                path = self._first_mapping_path(item)
                if path:
                    return path
        if isinstance(mapping, dict) and "path" in mapping:
            return str(mapping["path"])
        return ""

    def _path_get(self, data: Any, path: str) -> Any:
        if path == "$":
            return data
        cleaned = path[2:] if path.startswith("$.") else path
        if not cleaned:
            return data
        parts = self._path_parts(cleaned)
        cur = data
        for part in parts:
            if isinstance(cur, dict):
                if part not in cur:
                    return None
                cur = cur[part]
            elif isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return cur

    def _path_parts(self, path: str) -> list[str]:
        expanded = re.sub(r"\[(\d+)\]", r".\1", path)
        return [part for part in expanded.split(".") if part]

    def _assign_nested(self, target: dict[str, Any], path: str, value: Any) -> None:
        parts = self._path_parts(path)
        if not parts:
            return
        cur = target
        for part in parts[:-1]:
            next_value = cur.get(part)
            if not isinstance(next_value, dict):
                next_value = {}
                cur[part] = next_value
            cur = next_value
        cur[parts[-1]] = value

    def _merge_dict(self, target: dict[str, Any], updates: dict[str, Any]) -> None:
        for key, value in updates.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                self._merge_dict(target[key], value)
            else:
                target[key] = value

    def _map_value(self, value: Any, mapping: dict[str, str]) -> str:
        text = "" if value is None else str(value).strip()
        return mapping.get(text, mapping.get(text.lower(), text))

    def _apply_transform(self, value: Any, transform: str) -> Any:
        if transform == "rasp_sink_from_stacktrace":
            return self._derive_rasp_sink(value)
        return value

    def _derive_rasp_sink(self, stacktrace: Any) -> str:
        frames = self._stack_frames(stacktrace)
        if not frames:
            return ""
        sink_needles = [
            ".lookup",
            ".connect",
            ".query",
            ".execute",
            ".executequery",
            ".exec",
            ".start",
            ".eval",
            ".deserialize",
            ".readobject",
            ".loadclass",
            ".openconnection",
        ]
        framework_needles = [
            "controller.",
            "filterchain.",
            "dispatcherservlet.",
            "frameworkservlet.",
            "threadpoolexecutor.",
            "taskthread.",
            "socketprocessor",
            "reflect.",
        ]
        for frame in frames:
            normalized = frame.lower()
            if any(needle in normalized for needle in sink_needles):
                return self._frame_symbol(frame)
        for frame in frames:
            normalized = frame.lower()
            if not any(needle in normalized for needle in framework_needles):
                return self._frame_symbol(frame)
        return self._frame_symbol(frames[0])

    def _stack_frames(self, value: Any) -> list[str]:
        if isinstance(value, list):
            frames: list[str] = []
            for item in value:
                frames.extend(self._stack_frames(item))
            return frames
        if isinstance(value, str):
            return [line.strip() for line in value.splitlines() if line.strip()]
        if isinstance(value, dict):
            # Structured frame objects (e.g. {"method": "...", "file": "...",
            # "line": 12}) are a common vendor format — collapse them into a
            # single symbol string so sink derivation still works.
            parts = []
            for key in ("method", "function", "class", "file", "line", "lineno"):
                if value.get(key) is not None:
                    parts.append(str(value[key]))
            if parts:
                return [" ".join(parts)]
            return []
        return []

    def _frame_symbol(self, frame: str) -> str:
        symbol = frame.split("(", 1)[0].strip()
        return symbol or frame.strip()

    def _build_adapter_evidence(self, profile: MappingProfile, log: dict[str, Any]) -> list[dict[str, Any]]:
        evidence = []
        for idx, item in enumerate(profile.evidence_fields):
            if not isinstance(item, dict):
                continue
            value = self._resolve_mapping(item.get("path"), log)
            if value in ("", None):
                continue
            evidence.append(
                {
                    "ref": f"mapping:{profile.profile_id}:{idx}",
                    "source": profile.profile_id,
                    "type": str(item.get("type") or "mapped_field"),
                    "value": value,
                    "why_it_matters": str(item.get("why_it_matters") or item.get("label") or "日志适配配置提取的证据字段。"),
                }
            )
        return evidence

    def _field_mapping_hints(self, profile: MappingProfile, errors: list[str]) -> dict[str, str]:
        missing = [item.split(":", 1)[1] for item in errors if item.startswith("missing_required_field:")]
        return {field: DEFAULT_REQUIRED_FIELD_HINTS.get(field, f"请在 profile.mappings 中配置 {field} 的 JSON path。") for field in missing}

    def _raw_alert_preview(self, raw_alert: RawAlert | None, mapped: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        if raw_alert:
            return {
                "alert_id": raw_alert.alert_id,
                "source": raw_alert.source,
                "product": raw_alert.product,
                "event_type": raw_alert.event_type,
                "severity": raw_alert.severity,
                "timestamp": raw_alert.timestamp,
                "payload": raw_alert.payload,
            }
        return {
            "alert_id": mapped.get("alert_id"),
            "source": mapped.get("source"),
            "product": mapped.get("product"),
            "event_type": mapped.get("event_type"),
            "severity": mapped.get("severity"),
            "timestamp": mapped.get("timestamp"),
            "payload": payload,
        }


def mapping_profile_record(profile: MappingProfile) -> dict[str, Any]:
    return {
        "profile_id": profile.profile_id,
        "name": profile.name,
        "version": profile.version,
        "description": profile.description,
        "enabled": profile.enabled,
        "profile_json": json.dumps(profile.to_dict(), ensure_ascii=False, sort_keys=True),
        "created_at_ms": now_ms(),
        "updated_at_ms": now_ms(),
    }
