from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import zlib
from collections import Counter
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl

from .config import PolicyConfig
from .json_safety import loads_bounded_json
from .models import (
    RawAlert,
    new_id,
    now_ms,
    strip_server_owned_alert_payload_fields,
)
from .normalizer import EventNormalizer
from .policy import PolicyEngine


SUPPORTED_PRODUCTS = {"hips", "rasp", "ndr", "waf", "siem"}
PRODUCT_LABELS = {"hips": "HIPS", "rasp": "RASP", "ndr": "NDR", "waf": "WAF", "siem": "SIEM"}
DEFAULT_REQUIRED_FIELDS = ["alert_id", "product", "event_type", "severity", "timestamp"]
_MODEL_ENTITY_TARGETS = {
    "action",
    "app",
    "dst_ip",
    "host",
    "method",
    "process",
    "rule",
    "src_ip",
    "url",
    "user",
}
RASP_ALERT_ID_PATHS = [
    "$.metadata.id",
    "$.alert.id",
    "$.event.ID",
    "$.event.id",
    "$.event.request_id",
    "$.request_id",
    "$.id",
    "$.trace.id",
]
_TIMESTAMP_OFFSET_RE = re.compile(r"^([+-])(\d{2}):(\d{2})$")
_RASP_CONTEXT_MAX_ITEMS = 20
_RASP_CONTEXT_MAX_LEAVES = 64
_RASP_CONTEXT_MAX_TEXT = 16_384
_RASP_EVIDENCE_MAX_DEPTH = 6
_RASP_EVIDENCE_MAX_NODES = 128
_RASP_EVIDENCE_MAX_ENTRIES = 8
_RASP_EVIDENCE_MAX_VALUE_BYTES = 384
_RASP_BASE64_MAX_ENCODED_BYTES = 16_384
_RASP_BASE64_MAX_DECODED_BYTES = 12_288
_RASP_DECOMPRESSED_MAX_BYTES = 32_768
_RASP_RUNTIME_MAX_CORRELATIONS = 4
_TRUSTED_TRANSPORT_MARKER = "_gateway_transport_trusted"
_RASP_SEMANTIC_FIELD_NAMES = {
    "class",
    "class_loader",
    "class_name",
    "classloader",
    "classname",
    "cmd",
    "command",
    "domain",
    "expression",
    "file",
    "file_name",
    "filename",
    "absolute_path",
    "host",
    "hit_evidence",
    "lib",
    "library",
    "library_path",
    "method",
    "native_library",
    "native_library_path",
    "path",
    "payload",
    "protocol",
    "script",
    "sql",
    "suffix",
    "url",
    "xss",
}
_RASP_EVIDENCE_WRAPPER_FIELD_NAMES = {
    "rasp_raw_data",
}
_RASP_REQUEST_ATTACK_FIELD_NAMES = {
    "class",
    "class_loader",
    "class_name",
    "classloader",
    "classname",
    "cmd",
    "command",
    "expression",
    "script",
    "sql",
    "suffix",
    "xss",
}
_RASP_HOOK_ATTACK_FIELD_NAMES = _RASP_SEMANTIC_FIELD_NAMES - {"payload"}
_RASP_EXPLICIT_ATTACK_INDICATORS = {
    "expression_execution_reference",
    "java_file_api_reference",
    "java_deserialization_hint",
    "jdbc_connection_reference",
    "jndi_reference",
    "ognl_object_construction_reference",
    "path_traversal_reference",
    "process_execution_reference",
    "script_execution_reference",
    "sensitive_method_chain_reference",
    "sql_injection_reference",
    "smb_reference",
    "unc_path_reference",
    "xss_reference",
}
_RASP_SENSITIVE_FIELD_MARKERS = {
    "account_number",
    "api_key",
    "authorization",
    "bank_card",
    "card_number",
    "client_secret",
    "cookie",
    "credential",
    "customer_id",
    "email",
    "id_card",
    "identity_card",
    "jsessionid",
    "mobile",
    "password",
    "passwd",
    "phone",
    "proxy_authorization",
    "pwd",
    "refresh_token",
    "secret",
    "session",
    "session_id",
    "set_cookie",
    "ssn",
    "token",
    "x_api_key",
}
_RASP_INDICATORS = (
    (
        "unc_path_reference",
        re.compile(
            r"(?<![\\])\\\\(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|"
            r"(?:\d{1,3}\.){3}\d{1,3})\\[^\\/\s]+(?:\\[^\\\r\n]*)?",
            re.IGNORECASE,
        ),
    ),
    ("smb_reference", re.compile(r"\bsmb://[^/\s]+/[^?\s]+", re.IGNORECASE)),
    (
        "native_library_reference",
        re.compile(r"(?:^|[/\\])[^/\\\r\n]+\.(?:dll|so|dylib)\b", re.IGNORECASE),
    ),
    (
        "ognl_object_construction_reference",
        re.compile(
            r"\bnew\s+(?:java|javax|ognl|com\.opensymphony)"
            r"(?:\.[a-z_$][\w$]*)+\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "java_file_api_reference",
        re.compile(r"\bjava\.io\.File\s*\(", re.IGNORECASE),
    ),
    (
        "sensitive_method_chain_reference",
        re.compile(
            r"(?:\.list(?:Files)?|\.delete|\.renameTo|\.getRuntime\s*\(\s*\)"
            r"\s*\.exec|\.forName|\.newInstance|\.getDeclaredMethod)\s*\(",
            re.IGNORECASE,
        ),
    ),
    ("jndi_reference", re.compile(r"\b(?:ldap|rmi|iiop|dns)://", re.IGNORECASE)),
    ("jdbc_connection_reference", re.compile(r"\bjdbc:[a-z0-9_+.-]+:", re.IGNORECASE)),
    ("java_deserialization_hint", re.compile(r"@type|objectinputstream|readobject|serialization", re.IGNORECASE)),
    ("process_execution_reference", re.compile(r"processbuilder|runtime\.getruntime|\.exec\(|cmd\.exe|/bin/(?:sh|bash)", re.IGNORECASE)),
    ("expression_execution_reference", re.compile(r"\$\{|#\{|\bspel\b|\bognl\b|\bmvel\b|\bjexl\b", re.IGNORECASE)),
    ("script_execution_reference", re.compile(r"\b(?:javascript|groovy|rhino|nashorn)\b", re.IGNORECASE)),
    ("external_url_reference", re.compile(r"\b(?:https?|ftp)://", re.IGNORECASE)),
    ("sql_injection_reference", re.compile(r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1|\b(?:sleep|benchmark|load_file)\s*\()", re.IGNORECASE)),
    ("path_traversal_reference", re.compile(r"(?:\.\.[/\\]|%2e%2e(?:%2f|/|%5c))", re.IGNORECASE)),
    ("xss_reference", re.compile(r"(?:<\s*script\b|javascript\s*:|\bon(?:error|load)\s*=)", re.IGNORECASE)),
)

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


def validate_raw_alert(alert: RawAlert) -> RawAlert:
    """Validate the stable RawAlert contract at every ingestion boundary.

    Keeping this next to the adapter lets dry-run use the *same* contract as
    production submission, rather than only checking whether mapped keys exist.
    """
    alert.product = str(alert.product or "").strip().lower()
    if alert.product not in SUPPORTED_PRODUCTS:
        raise ValueError(f"unsupported product: {alert.product or '<empty>'}")
    alert.source = str(alert.source or "").strip()
    if not alert.source:
        raise ValueError("source is required")
    if len(alert.source) > 256:
        raise ValueError("source is too long")
    alert.event_type = str(alert.event_type or "").strip()
    if not alert.event_type or alert.event_type == "unknown":
        raise ValueError("event_type is required")
    if len(alert.event_type) > 256:
        raise ValueError("event_type is too long")
    severity = str(alert.severity or "").strip().lower()
    alert.severity = DEFAULT_SEVERITY_MAP.get(severity, severity)
    if alert.severity not in {"critical", "high", "medium", "low"}:
        raise ValueError("severity must be critical, high, medium, or low")
    alert.alert_id = str(alert.alert_id or "").strip() or new_id("alert")
    if len(alert.alert_id) > 256:
        raise ValueError("alert_id is too long")
    if not isinstance(alert.payload, dict):
        raise ValueError("payload must be a JSON object")
    timestamp = str(alert.timestamp or "").strip()
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if len(timestamp) > 64:
        raise ValueError("timestamp is too long")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be an ISO-8601 value") from exc
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset")
    alert.timestamp = timestamp
    return alert


def apply_timestamp_offset(timestamp: Any, offset: str) -> tuple[str, bool]:
    """Attach a profile-owned offset to a timezone-naive ISO-8601 value."""
    rendered = str(timestamp or "").strip()
    if not rendered:
        return rendered, False
    try:
        parsed = datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError:
        return rendered, False
    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        return rendered, False
    match = _TIMESTAMP_OFFSET_RE.fullmatch(str(offset or "").strip())
    if not match:
        return rendered, False
    hours = int(match.group(2))
    minutes = int(match.group(3))
    if hours > 14 or minutes > 59 or (hours == 14 and minutes):
        raise ValueError("timestamp_offset must be between -14:00 and +14:00")
    delta = timedelta(hours=hours, minutes=minutes)
    if match.group(1) == "-":
        delta = -delta
    return parsed.replace(tzinfo=timezone(delta)).isoformat(), True

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
    timestamp_offset: str = ""

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
            timestamp_offset=str(data.get("timestamp_offset") or "").strip(),
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
            "timestamp_offset": self.timestamp_offset,
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
        version="v7",
        description="示例：把常见 RASP JSON 日志映射为内部 RawAlert，并保留 host、time、stacktrace、hook 和 trace 关键上下文。",
        mappings={
            "alert_id": list(RASP_ALERT_ID_PATHS),
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
            "payload.request_parameters": [
                {"path": "$.event.request_message.parameter", "transform": "rasp_request_parameter_summary"},
                {"path": "$.request_message.parameter", "transform": "rasp_request_parameter_summary"},
                {"path": "$.request.parameters", "transform": "rasp_request_parameter_summary"},
                {"path": "$.http.request.parameters", "transform": "rasp_request_parameter_summary"},
            ],
            "payload.request_context": [
                {"path": "$.event.request_message", "transform": "rasp_request_context"},
                {"path": "$.request_message", "transform": "rasp_request_context"},
                {"path": "$.http.request", "transform": "rasp_request_context"},
            ],
            "payload.hook_data": ["$.hook_data", "$.items[0].hook_data", "$.attack.hook_data"],
            "payload.rasp_items_context": {"path": "$.items", "transform": "rasp_items_context"},
            "payload.rasp_evidence_integrity": {"path": "$", "transform": "rasp_evidence_integrity"},
            "payload.taint_source": ["$.taint.source", "$.attack.taint_source"],
            "payload.sink": ["$.sink", "$.attack.sink", {"path": "$.items[0].stacktrace", "transform": "rasp_sink_from_stacktrace"}],
            "payload.exception": ["$.exception.message", "$.exception", "$.attack.exception"],
        },
        product_map={"runtime_app_protection": "rasp", "runtime_application_self_protection": "rasp", "rasp": "rasp"},
        timestamp_offset="+08:00",
        evidence_fields=[
            {
                "type": "request_context",
                "path": [
                    {"path": "$.event.request_message", "transform": "rasp_request_context"},
                    {"path": "$.request_message", "transform": "rasp_request_context"},
                    {"path": "$.http.request", "transform": "rasp_request_context"},
                ],
                "why_it_matters": "请求参数与请求体仅保留命中明确攻击特征的受控片段；完整原文仍保存在受保护的原始告警中。",
            },
            {
                "type": "request_parameters",
                "path": [
                    {"path": "$.event.request_message.parameter", "transform": "rasp_request_parameter_summary"},
                    {"path": "$.request_message.parameter", "transform": "rasp_request_parameter_summary"},
                    {"path": "$.request.parameters", "transform": "rasp_request_parameter_summary"},
                    {"path": "$.http.request.parameters", "transform": "rasp_request_parameter_summary"},
                ],
                "why_it_matters": "请求参数仅保留命中明确攻击特征的受控片段；空对象表示上游未提供有效请求参数，而非网关丢失字段。",
            },
            {
                "type": "hook_data",
                "path": [
                    {"path": "$.hook_data", "transform": "rasp_hook_data_summary"},
                    {"path": "$.items[0].hook_data", "transform": "rasp_hook_data_summary"},
                    {"path": "$.attack.hook_data", "transform": "rasp_hook_data_summary"},
                ],
                "why_it_matters": "hook_data 仅投影规则相关字段的脱敏、限长原值，并保留完整原文的受保护引用。",
            },
            {
                "type": "rasp_items_context",
                "path": {"path": "$.items", "transform": "rasp_items_context"},
                "why_it_matters": "完整 items[] 摘要保留每个 RASP 规则、动作、hook_data 状态和调用栈状态，避免仅分析第一条规则。",
            },
            {
                "type": "rasp_evidence_integrity",
                "path": {"path": "$", "transform": "rasp_evidence_integrity"},
                "why_it_matters": "完整性摘要记录原始 RASP 日志指纹、请求字段状态和 items 数量，便于定位上游与网关之间的证据边界。",
            },
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
        profile.version = "v8"
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


def ensure_rasp_evidence_coverage(profile: MappingProfile) -> tuple[list[str], list[str]]:
    """Add missing RASP evidence and CloudRASP identity coverage safely."""
    baseline = demo_rasp_profile()
    added_mappings: list[str] = []
    added_evidence: list[str] = []

    for target in (
        "payload.request_parameters",
        "payload.hook_data",
        "payload.request_context",
        "payload.rasp_items_context",
        "payload.rasp_evidence_integrity",
    ):
        if target not in profile.mappings:
            profile.mappings[target] = baseline.mappings[target]
            added_mappings.append(target)

    alert_id_mapping = profile.mappings.get("alert_id")
    if not _mapping_includes_path(alert_id_mapping, "$.event.ID"):
        if alert_id_mapping in (None, "", []):
            profile.mappings["alert_id"] = ["$.event.ID"]
        elif isinstance(alert_id_mapping, list):
            profile.mappings["alert_id"] = [*alert_id_mapping, "$.event.ID"]
        else:
            profile.mappings["alert_id"] = [alert_id_mapping, "$.event.ID"]
        added_mappings.append("alert_id:$.event.ID")

    existing_types = {
        str(item.get("type") or "").strip().lower()
        for item in profile.evidence_fields
        if isinstance(item, dict)
    }
    for field in baseline.evidence_fields:
        evidence_type = str(field.get("type") or "").strip().lower()
        if evidence_type not in {
            "request_context",
            "request_parameters",
            "hook_data",
            "rasp_items_context",
            "rasp_evidence_integrity",
        } or evidence_type in existing_types:
            continue
        profile.evidence_fields.append(field)
        existing_types.add(evidence_type)
        added_evidence.append(evidence_type)
    return added_mappings, added_evidence


def _mapping_includes_path(mapping: Any, path: str) -> bool:
    if isinstance(mapping, str):
        return mapping == path
    if isinstance(mapping, dict):
        return mapping.get("path") == path
    if isinstance(mapping, list):
        return any(_mapping_includes_path(item, path) for item in mapping)
    return False


class LogAdapter:
    def __init__(self, normalizer: EventNormalizer | None = None):
        self.normalizer = normalizer
        self.policy = normalizer.policy if normalizer is not None else PolicyEngine(PolicyConfig())

    def adapt(
        self,
        profile: MappingProfile,
        log: dict[str, Any],
        *,
        trusted_syslog_envelope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        input_log = dict(log)
        for key in list(input_log):
            if str(key).casefold() == "_syslog_envelope":
                input_log.pop(key, None)
        nested_log = input_log.get("log")
        if isinstance(nested_log, dict):
            nested_log = dict(nested_log)
            for key in list(nested_log):
                if str(key).casefold() == "_syslog_envelope":
                    nested_log.pop(key, None)
            input_log["log"] = nested_log
        log, envelope = self.unwrap_syslog_envelope(input_log)
        log = dict(log)
        if isinstance(envelope, dict):
            envelope = dict(envelope)
            envelope.pop(_TRUSTED_TRANSPORT_MARKER, None)
            log["_syslog_envelope"] = envelope
        if isinstance(trusted_syslog_envelope, dict):
            envelope = dict(trusted_syslog_envelope)
            envelope.pop(_TRUSTED_TRANSPORT_MARKER, None)
            envelope[_TRUSTED_TRANSPORT_MARKER] = True
            log["_syslog_envelope"] = envelope
        errors: list[str] = []
        warnings: list[str] = ["已从 Syslog envelope 的 JSON message 中提取原始日志。"] if envelope else []
        mapped: dict[str, Any] = {}
        entities: dict[str, Any] = {}
        payload_fields: dict[str, Any] = {}

        profile_product = self._map_value(
            self._resolve_mapping(profile.mappings.get("product"), log),
            profile.product_map,
        ).lower()
        rasp_runtime_context = (
            self._build_rasp_runtime_context(log)
            if profile_product == "rasp"
            else None
        )
        rasp_model_mappings = demo_rasp_profile().mappings if profile_product == "rasp" else {}
        for target, source in profile.mappings.items():
            if profile_product == "rasp" and (
                target in {"alert_id", "event_type", "payload"}
                or target.startswith("entities.")
                or target.startswith("payload.")
            ):
                source = self._filter_mapping_to_reference(
                    source,
                    rasp_model_mappings.get(target),
                )
                if source is None:
                    continue
            value = self._resolve_mapping(
                source,
                log,
                rasp_runtime_context=rasp_runtime_context,
            )
            if value in ("", None):
                continue
            if target.startswith("entities."):
                entity_name = target.split(".", 1)[1]
                if entity_name in _MODEL_ENTITY_TARGETS:
                    entities[entity_name] = value
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
        if mapped.get("timestamp") not in (None, ""):
            try:
                mapped["timestamp"], offset_applied = apply_timestamp_offset(
                    mapped["timestamp"], profile.timestamp_offset
                )
            except ValueError as exc:
                errors.append(f"invalid_timestamp_offset:{exc}")
            else:
                if offset_applied:
                    warnings.append(
                        f"timestamp 缺少时区，已按 profile 配置补充 {profile.timestamp_offset}。"
                    )

        for required_field in profile.required_fields:
            if required_field not in mapped or mapped.get(required_field) in ("", None):
                errors.append(f"missing_required_field:{required_field}")

        if mapped.get("product") and mapped["product"] not in SUPPORTED_PRODUCTS:
            errors.append(f"unsupported_product:{mapped['product']}")

        if mapped.get("severity") and mapped["severity"] not in {"critical", "high", "medium", "low"}:
            errors.append(f"unsupported_severity:{mapped['severity']}")

        payload = (
            {}
            if mapped.get("product") == "rasp"
            else dict(mapped.get("payload") or {})
        )
        strip_server_owned_alert_payload_fields(payload)
        self._merge_dict(payload, payload_fields)
        strip_server_owned_alert_payload_fields(payload)
        if mapped.get("product") == "rasp":
            integrity = self._summarize_rasp_evidence_integrity(log)
            if integrity:
                payload["rasp_evidence_integrity"] = integrity
        clean_log = dict(log)
        clean_envelope = clean_log.get("_syslog_envelope")
        if isinstance(clean_envelope, dict):
            clean_envelope = dict(clean_envelope)
            clean_envelope.pop(_TRUSTED_TRANSPORT_MARKER, None)
            clean_log["_syslog_envelope"] = clean_envelope
        payload["original_log"] = clean_log
        if envelope:
            public_envelope = dict(envelope)
            public_envelope.pop(_TRUSTED_TRANSPORT_MARKER, None)
            payload["syslog_envelope"] = public_envelope
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

        adapter_evidence = self._build_adapter_evidence(
            profile,
            log,
            product=str(mapped.get("product") or ""),
            rasp_runtime_context=rasp_runtime_context,
        )
        if adapter_evidence:
            payload["adapter_evidence"] = adapter_evidence

        raw_alert = None
        if not errors:
            candidate = RawAlert(
                source=str(mapped["source"]),
                product=str(mapped["product"]),
                event_type=str(mapped["event_type"]),
                severity=str(mapped["severity"]),
                timestamp=str(mapped["timestamp"]),
                payload=payload,
                alert_id=str(mapped["alert_id"]),
            )
            try:
                raw_alert = validate_raw_alert(candidate)
            except ValueError as exc:
                errors.append(f"invalid_raw_alert:{exc}")
                payload["adapter"]["mapping_status"] = "failed"
                payload["adapter"]["contract_validation_error"] = str(exc)

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
        log, envelope = self.unwrap_syslog_envelope(log)
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

            if target == "product" and product_signal and (not match or product_signal["confidence"] > match["confidence"]):
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
            "input": {"syslog_envelope_detected": bool(envelope)},
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

    def unwrap_syslog_envelope(self, log: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Decode JSON carried by common Syslog/collector envelope fields.

        The returned payload retains a compact envelope under
        ``_syslog_envelope`` so a mapping can still use transport metadata such
        as hostname without forcing users to hand-edit the original message.
        """
        if not isinstance(log, dict):
            return log, None
        nested = log.get("log")
        if isinstance(nested, dict):
            decoded = dict(nested)
        else:
            text = log.get("message")
            if not isinstance(text, str):
                event = log.get("event")
                text = event.get("original") if isinstance(event, dict) else None
            if not isinstance(text, str):
                return log, None
            try:
                decoded_value = loads_bounded_json(text)
            except (TypeError, ValueError, json.JSONDecodeError):
                return log, None
            if not isinstance(decoded_value, dict):
                return log, None
            decoded = decoded_value
        envelope = {
            key: value
            for key, value in log.items()
            if key not in {"log", "message", "event"}
        }
        event = log.get("event")
        if isinstance(event, dict):
            envelope["event"] = {key: value for key, value in event.items() if key != "original"}
        decoded.setdefault("_syslog_envelope", envelope)
        return decoded, envelope

    def detect_product(self, log: dict[str, Any]) -> dict[str, Any] | None:
        """Return a high-confidence product classification for auto mapping."""
        decoded, _ = self.unwrap_syslog_envelope(log)
        return self._product_signal(decoded, self._flatten_paths(decoded), None)

    def _resolve_mapping(
        self,
        mapping: Any,
        log: dict[str, Any],
        *,
        rasp_runtime_context: dict[str, Any] | None = None,
    ) -> Any:
        if isinstance(mapping, list):
            for item in mapping:
                value = self._resolve_mapping(
                    item,
                    log,
                    rasp_runtime_context=rasp_runtime_context,
                )
                if value not in ("", None):
                    return value
            return None
        if isinstance(mapping, dict):
            if "literal" in mapping:
                return mapping["literal"]
            if "path" in mapping:
                value = self._path_get(log, str(mapping["path"]))
                return self._apply_transform(
                    value,
                    str(mapping.get("transform") or ""),
                    rasp_runtime_context=rasp_runtime_context,
                )
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

    def _product_signal(self, log: dict[str, Any], flat: dict[str, Any], fallback_product: str | None = "rasp") -> dict[str, Any] | None:
        text = json.dumps(log, ensure_ascii=False).lower()
        product_match = self._best_path_match(flat, ["product", "device.type", "source.product", "event.product"])
        if product_match:
            value = str(product_match["value"]).lower()
            aliases = {
                "runtime_app_protection": "rasp",
                "runtime_application_self_protection": "rasp",
                "web_application_firewall": "waf",
                "host_intrusion_prevention": "hips",
                "network_detection_response": "ndr",
                "security_information_event_management": "siem",
            }
            if value in aliases:
                return {"product": aliases[value], "confidence": 0.98}
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
        if best_score == 1 and fallback_product in SUPPORTED_PRODUCTS:
            return {"product": fallback_product, "confidence": 0.62}
        return {"product": fallback_product, "confidence": 0.0} if fallback_product in SUPPORTED_PRODUCTS else None

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

    def _apply_transform(
        self,
        value: Any,
        transform: str,
        *,
        rasp_runtime_context: dict[str, Any] | None = None,
    ) -> Any:
        if transform == "rasp_sink_from_stacktrace":
            return self._derive_rasp_sink(value)
        if transform == "rasp_request_parameter_summary":
            return self._summarize_rasp_request_parameters(
                value,
                runtime_context=rasp_runtime_context,
            )
        if transform == "rasp_request_context":
            return self._summarize_rasp_request_context(
                value,
                runtime_context=rasp_runtime_context,
            )
        if transform == "rasp_hook_data_summary":
            return self._summarize_rasp_hook_data(value)
        if transform == "rasp_items_context":
            return self._summarize_rasp_items_context(value)
        if transform == "rasp_evidence_integrity":
            return self._summarize_rasp_evidence_integrity(value)
        return value

    def _build_rasp_runtime_context(
        self,
        log: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Build a value-free correlation summary from vendor-owned RASP items.

        Request payload projection must not infer relevance from an endpoint name
        alone.  A correlation is retained only when a vendor rule is accompanied
        by a security-relevant runtime sink and either a controlled hook field or
        an explicit stack indicator.  Hook values and stack frames never enter
        this context.
        """
        if not isinstance(log, dict):
            return None
        items = log.get("items")
        if not isinstance(items, list):
            return None

        correlations: list[dict[str, Any]] = []
        for index, item in enumerate(items[:_RASP_CONTEXT_MAX_ITEMS]):
            if not isinstance(item, dict):
                continue
            rule_id = self._safe_rasp_label(item.get("rule_id"), limit=128)
            rule_name = self._safe_rasp_label(item.get("rule_name"), limit=160)
            if not (rule_id or rule_name):
                continue
            hook_data = item.get("hook_data")
            hook_fields = []
            if isinstance(hook_data, dict):
                hook_fields = sorted(
                    {
                        self._canonical_rasp_field_name(key)
                        for key, value in hook_data.items()
                        if value not in (None, "", [], {})
                        and self._canonical_rasp_field_name(key)
                        in _RASP_HOOK_ATTACK_FIELD_NAMES
                    }
                )[:8]
            stacktrace = item.get("stacktrace") or item.get("stack_trace")
            stack_indicators = sorted(
                set(self._rasp_indicator_categories(stacktrace))
                & _RASP_EXPLICIT_ATTACK_INDICATORS
            )[:8]
            sink = self._derive_rasp_sink(stacktrace)
            if not self._rasp_sink_is_security_relevant(sink):
                continue
            if not (hook_fields or stack_indicators):
                continue
            correlations.append(
                {
                    "item_index": index,
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "sink": self._safe_rasp_label(sink, limit=200),
                    "hook_fields": hook_fields,
                    "stack_indicator_categories": stack_indicators,
                }
            )
            if len(correlations) >= _RASP_RUNTIME_MAX_CORRELATIONS:
                break

        if not correlations:
            return None
        return {
            "security_relevance": "runtime_correlated",
            "correlations": correlations,
            "truncated": len(items) > _RASP_CONTEXT_MAX_ITEMS,
        }

    @staticmethod
    def _rasp_sink_is_security_relevant(sink: str) -> bool:
        normalized = str(sink or "").casefold()
        return any(
            marker in normalized
            for marker in (
                ".connect",
                ".delete",
                ".deserialize",
                ".eval",
                ".exec",
                ".execute",
                ".executequery",
                ".list",
                ".load",
                ".loadclass",
                ".lookup",
                ".openconnection",
                ".query",
                ".readobject",
                ".renameto",
                ".start",
            )
        )

    def _summarize_rasp_request_parameters(
        self,
        value: Any,
        *,
        runtime_context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Retain bounded attack semantics while filtering unrelated request data."""
        if value is None:
            return None
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return {"state": "empty", "format": "text"}
            try:
                value = loads_bounded_json(text)
            except (TypeError, ValueError, json.JSONDecodeError):
                return {
                    "state": "present",
                    "format": "text",
                    "length": len(text),
                    "selected_evidence": self._project_rasp_attack_evidence(
                        value,
                        source="request_parameters",
                        direct_fields=_RASP_REQUEST_ATTACK_FIELD_NAMES,
                        runtime_context=runtime_context,
                    ),
                }

        if isinstance(value, dict):
            if not value:
                return {"state": "empty", "format": "json_object"}
            summary = {"state": "present", "format": "json_object", "field_count": len(value)}
            summary["selected_evidence"] = self._project_rasp_attack_evidence(
                value,
                source="request_parameters",
                direct_fields=_RASP_REQUEST_ATTACK_FIELD_NAMES,
                runtime_context=runtime_context,
            )
            return summary
        if isinstance(value, list):
            if not value:
                return {"state": "empty", "format": "json_array"}
            summary = {"state": "present", "format": "json_array", "item_count": len(value)}
            summary["selected_evidence"] = self._project_rasp_attack_evidence(
                value,
                source="request_parameters",
                direct_fields=_RASP_REQUEST_ATTACK_FIELD_NAMES,
                runtime_context=runtime_context,
            )
            return summary
        summary = {"state": "present", "format": type(value).__name__}
        summary["selected_evidence"] = self._project_rasp_attack_evidence(
            value,
            source="request_parameters",
            direct_fields=_RASP_REQUEST_ATTACK_FIELD_NAMES,
            runtime_context=runtime_context,
        )
        return summary

    def _summarize_rasp_request_context(
        self,
        value: Any,
        *,
        runtime_context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Project HTTP context into a model-safe, evidence-preserving summary.

        The original request remains under ``payload.original_log`` for audited
        analyst review. This projection carries presence, structure, semantic
        indicators and a stable fingerprint so an LLM can reason about the
        signal without receiving a replayable request body.
        """
        if not isinstance(value, dict):
            return None
        parameter = self._summarize_rasp_value(value.get("parameter"))
        body = self._summarize_rasp_value(value.get("body"))
        if parameter.get("state") == "present":
            parameter["selected_evidence"] = self._project_rasp_attack_evidence(
                value.get("parameter"),
                source="request_parameter",
                direct_fields=_RASP_REQUEST_ATTACK_FIELD_NAMES,
                runtime_context=runtime_context,
            )
        if body.get("state") == "present":
            body["selected_evidence"] = self._project_rasp_attack_evidence(
                value.get("body"),
                source="request_body",
                direct_fields=_RASP_REQUEST_ATTACK_FIELD_NAMES,
                runtime_context=runtime_context,
            )
        headers = value.get("header") or value.get("headers")
        header_names = []
        if isinstance(headers, dict):
            header_names = sorted(
                str(key).lower()[:64]
                for key in headers
                if str(key).lower() in {"content-type", "content-length", "user-agent", "host"}
            )
        return {
            "state": "present" if value else "empty",
            "method": self._safe_rasp_label(value.get("method"), limit=16),
            "url_present": value.get("url") not in (None, ""),
            "parameter": parameter,
            "body": body,
            "headers": {
                "state": "present" if isinstance(headers, dict) and headers else "empty",
                "field_count": len(headers) if isinstance(headers, dict) else 0,
                "recognized_names": header_names,
            },
            "raw_evidence_retained": any(
                item.get("state") == "present" for item in (parameter, body)
            ),
        }

    def _summarize_rasp_hook_data(self, value: Any) -> dict[str, Any] | None:
        """Expose selected hook values while retaining the full raw value only in storage."""
        summary = self._summarize_rasp_value(value)
        if summary.get("state") == "missing":
            return None
        if isinstance(value, dict):
            fields: dict[str, dict[str, Any]] = {}
            for key, item in value.items():
                name = self._canonical_rasp_field_name(key)
                if name in _RASP_SEMANTIC_FIELD_NAMES:
                    fields[name] = self._summarize_rasp_value(item)
            if fields:
                summary["semantic_fields"] = fields
        if summary.get("state") == "present":
            summary["selected_evidence"] = self._project_rasp_attack_evidence(
                value,
                source="hook_data",
                direct_fields=_RASP_HOOK_ATTACK_FIELD_NAMES,
            )
        summary["raw_evidence_retained"] = summary.get("state") == "present"
        return summary

    def _summarize_rasp_items_context(self, value: Any) -> dict[str, Any] | None:
        """Retain every RASP rule item as bounded semantic evidence.

        Legacy profiles select ``items[0]`` for headline fields. That remains
        useful for routing, but it must not hide a later rule's hook data or sink
        from analysis.
        """
        if not isinstance(value, list):
            return None
        projected: list[dict[str, Any]] = []
        for index, item in enumerate(value[:_RASP_CONTEXT_MAX_ITEMS]):
            if not isinstance(item, dict):
                continue
            stacktrace = item.get("stacktrace") or item.get("stack_trace")
            projected.append(
                {
                    "index": index,
                    "rule_id": self._safe_rasp_label(item.get("rule_id"), limit=128),
                    "rule_name": self._safe_rasp_label(item.get("rule_name"), limit=160),
                    "action": self._safe_rasp_label(item.get("intercept_state") or item.get("action"), limit=32),
                    "hook_data": self._summarize_rasp_hook_data(item.get("hook_data")),
                    "stacktrace": self._summarize_rasp_value(stacktrace),
                    "sink": self._derive_rasp_sink(stacktrace),
                }
            )
        return {
            "state": "present" if value else "empty",
            "item_count": len(value),
            "truncated": len(value) > _RASP_CONTEXT_MAX_ITEMS,
            "items": projected,
        }

    def _summarize_rasp_evidence_integrity(self, value: Any) -> dict[str, Any] | None:
        """Record a non-sensitive continuity marker from raw RASP log to analysis."""
        if not isinstance(value, dict):
            return None
        vendor_log = {key: item for key, item in value.items() if key != "_syslog_envelope"}
        serialized = self._rasp_serialized(vendor_log)
        envelope = value.get("_syslog_envelope") if isinstance(value.get("_syslog_envelope"), dict) else {}
        raw_syslog_message = envelope.get("raw_message")
        raw_syslog_bytes = (
            raw_syslog_message.encode("utf-8")
            if isinstance(raw_syslog_message, str)
            else b""
        )
        event = vendor_log.get("event") if isinstance(vendor_log.get("event"), dict) else {}
        request = event.get("request_message") if isinstance(event.get("request_message"), dict) else {}
        items = vendor_log.get("items") if isinstance(vendor_log.get("items"), list) else []
        summary: dict[str, Any] = {
            "version": "rasp-evidence-v1",
            "raw_log_bytes": len(serialized.encode("utf-8")),
            "raw_log_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
            "request_parameter_state": self._summarize_rasp_value(request.get("parameter")).get("state"),
            "request_body_state": self._summarize_rasp_value(request.get("body")).get("state"),
            "items_received": len(items),
            "items_with_hook_data": sum(
                1 for item in items if isinstance(item, dict) and item.get("hook_data") not in (None, "")
            ),
            "items_with_stacktrace": sum(
                1
                for item in items
                if isinstance(item, dict) and (item.get("stacktrace") or item.get("stack_trace"))
            ),
        }
        protocol = (
            self._safe_rasp_label(envelope.get("protocol"), limit=16)
            if envelope.get(_TRUSTED_TRANSPORT_MARKER) is True
            else ""
        )
        if protocol:
            summary["syslog_protocol"] = protocol
            summary["transport_assurance"] = (
                "collector_received_tcp"
                if protocol == "tcp"
                else "legacy_udp_best_effort"
                if protocol == "udp"
                else "transport_unknown"
            )
        if raw_syslog_bytes:
            summary.update(
                {
                    "syslog_raw_message_bytes": len(raw_syslog_bytes),
                    "syslog_raw_message_sha256": hashlib.sha256(raw_syslog_bytes).hexdigest(),
                }
            )
        return summary

    def _summarize_rasp_value(self, value: Any) -> dict[str, Any]:
        if value is None:
            return {"state": "missing"}
        decoded = value
        value_format = type(value).__name__
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return {"state": "empty", "format": "text", "length": 0}
            value_format = "text"
            try:
                parsed = loads_bounded_json(text)
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = None
            if isinstance(parsed, dict):
                decoded = parsed
                value_format = "json_object"
            elif isinstance(parsed, list):
                decoded = parsed
                value_format = "json_array"
        elif isinstance(value, dict):
            value_format = "json_object"
        elif isinstance(value, list):
            value_format = "json_array"

        raw_serialized = self._rasp_serialized(value)
        redacted_serialized = self._rasp_serialized(self.policy.redact(value))
        summary: dict[str, Any] = {
            "state": "empty" if decoded in ("", {}, []) else "present",
            "format": value_format,
            "length": len(raw_serialized.encode("utf-8")),
            "sha256": hashlib.sha256(redacted_serialized.encode("utf-8")).hexdigest(),
        }
        if isinstance(decoded, dict):
            summary["field_count"] = len(decoded)
            semantic_fields = {
                self._canonical_rasp_field_name(key)
                for key in decoded
                if self._canonical_rasp_field_name(key) in _RASP_SEMANTIC_FIELD_NAMES
            }
            if semantic_fields:
                summary["semantic_field_names"] = sorted(semantic_fields)
        elif isinstance(decoded, list):
            summary["item_count"] = len(decoded)
        indicators = self._rasp_indicator_categories(decoded)
        if indicators:
            summary["indicator_categories"] = indicators
        return summary

    def _project_rasp_attack_evidence(
        self,
        value: Any,
        *,
        source: str,
        direct_fields: set[str],
        runtime_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return a bounded, redacted projection of rule-relevant RASP values.

        Telemetry is always untrusted. Only allowlisted security fields or values
        matching deterministic attack indicators are reflected as values.  An
        encoded request payload may additionally be reflected as value-free
        metadata when the same vendor event contains a correlated RASP rule,
        controlled hook field and security-relevant runtime sink. Sensitive
        paths are dropped before hashing or projection, while selected values
        are policy-redacted and byte-bounded before they can enter model evidence.
        """
        entries: list[dict[str, Any]] = []
        nodes_scanned = 0
        projection_truncated = False
        encoded_candidate_seen = False
        unrecognized_security_fields: set[str] = set()
        inspection_states: set[str] = set()
        relevance_states: set[str] = set()
        decoded = self._decode_rasp_evidence_value(value, allow_form=True)
        runtime_correlations = (
            runtime_context.get("correlations", [])
            if source.startswith("request_") and isinstance(runtime_context, dict)
            else []
        )
        runtime_correlated = bool(runtime_correlations)

        configured_sensitive = {
            self._canonical_rasp_field_name(field)
            for field in getattr(self.policy.config, "redact_fields", [])
        }
        sensitive_fields = _RASP_SENSITIVE_FIELD_MARKERS | configured_sensitive

        def sensitive_field(name: str) -> bool:
            if name in sensitive_fields:
                return True
            parts = set(name.split("_"))
            return bool(
                parts
                & {
                    "account",
                    "authorization",
                    "card",
                    "cookie",
                    "credential",
                    "customer",
                    "email",
                    "identity",
                    "mobile",
                    "passwd",
                    "password",
                    "phone",
                    "pwd",
                    "secret",
                    "session",
                    "ssn",
                    "token",
                }
            )

        def safe_path(parent: str, field_name: str) -> str:
            if field_name in direct_fields or field_name in _RASP_EVIDENCE_WRAPPER_FIELD_NAMES:
                return f"{parent}.{field_name}"
            return f"{parent}.[filtered_field]"

        def correlation_metadata() -> dict[str, Any]:
            correlations = [
                item for item in runtime_correlations if isinstance(item, dict)
            ][:_RASP_RUNTIME_MAX_CORRELATIONS]
            return {
                "correlated_item_indexes": [
                    int(item["item_index"])
                    for item in correlations
                    if isinstance(item.get("item_index"), int)
                ],
                "correlated_rule_ids": sorted(
                    {
                        str(item.get("rule_id") or "")
                        for item in correlations
                        if item.get("rule_id")
                    }
                ),
                "correlated_sinks": sorted(
                    {
                        str(item.get("sink") or "")
                        for item in correlations
                        if item.get("sink")
                    }
                ),
                "correlated_hook_fields": sorted(
                    {
                        str(field)
                        for item in correlations
                        for field in item.get("hook_fields", [])
                        if field
                    }
                ),
            }

        def walk(
            node: Any,
            path: str,
            depth: int,
            direct: bool = False,
            encoded_payload_candidate: bool = False,
        ) -> None:
            nonlocal nodes_scanned, projection_truncated, encoded_candidate_seen
            if len(entries) >= _RASP_EVIDENCE_MAX_ENTRIES:
                projection_truncated = True
                return
            if depth > _RASP_EVIDENCE_MAX_DEPTH or nodes_scanned >= _RASP_EVIDENCE_MAX_NODES:
                projection_truncated = True
                return
            nodes_scanned += 1

            if isinstance(node, dict):
                ordered_items = sorted(
                    node.items(),
                    key=lambda pair: (
                        self._canonical_rasp_field_name(pair[0]) not in direct_fields,
                        str(pair[0]),
                    ),
                )
                for key, item in ordered_items:
                    name = self._canonical_rasp_field_name(key)
                    if sensitive_field(name):
                        continue
                    field_direct = name in direct_fields
                    field_is_payload_candidate = (
                        not field_direct
                        and any(
                            marker in name
                            for marker in ("payload", "raw_data")
                        )
                    )
                    if not field_direct and name not in _RASP_EVIDENCE_WRAPPER_FIELD_NAMES and any(
                        marker in name
                        for marker in ("lib", "library", "payload", "path", "raw_data")
                    ):
                        unrecognized_security_fields.add(name)
                    walk(
                        item,
                        safe_path(path, name),
                        depth + 1,
                        field_direct,
                        encoded_payload_candidate or field_is_payload_candidate,
                    )
                    if len(entries) >= _RASP_EVIDENCE_MAX_ENTRIES:
                        projection_truncated = True
                        break
                return
            if isinstance(node, list):
                for index, item in enumerate(node):
                    walk(
                        item,
                        f"{path}[{index}]",
                        depth + 1,
                        direct,
                        encoded_payload_candidate,
                    )
                    if len(entries) >= _RASP_EVIDENCE_MAX_ENTRIES:
                        projection_truncated = True
                        break
                return

            if isinstance(node, str) and not direct:
                allow_nested_form = any(
                    path.endswith(f".{name}")
                    for name in _RASP_EVIDENCE_WRAPPER_FIELD_NAMES
                )
                nested = self._decode_rasp_evidence_value(node, allow_form=allow_nested_form)
                if isinstance(nested, (dict, list)):
                    walk(
                        nested,
                        f"{path}.decoded",
                        depth + 1,
                        encoded_payload_candidate=encoded_payload_candidate,
                    )
                    return

            raw_text = node if isinstance(node, str) else self._rasp_serialized(node)
            encoded_profile = (
                self._inspect_rasp_encoded_value(raw_text)
                if not direct and encoded_payload_candidate
                else None
            )
            if isinstance(encoded_profile, dict):
                encoded_candidate_seen = True
                inspection_states.add(
                    str(
                        encoded_profile.get("content_inspection_status")
                        or "encoded_no_indicator_match"
                    )
                )
            inspection_text = (
                encoded_profile.get("_inspection_text")
                if isinstance(encoded_profile, dict)
                else None
            )
            indicators = self._rasp_indicator_categories(raw_text)
            if isinstance(inspection_text, str):
                indicators = sorted(
                    set(indicators)
                    | set(self._rasp_indicator_categories(inspection_text))
                )
            explicit_indicators = sorted(set(indicators) & _RASP_EXPLICIT_ATTACK_INDICATORS)
            if (
                not direct
                and not explicit_indicators
                and not (
                    runtime_correlated
                    and encoded_payload_candidate
                    and isinstance(encoded_profile, dict)
                )
            ):
                return

            if not direct and not explicit_indicators:
                evidence_bytes = raw_text.encode("utf-8", errors="replace")
                public_profile = {
                    key: item
                    for key, item in encoded_profile.items()
                    if not str(key).startswith("_")
                }
                content_status = str(
                    public_profile.get("content_inspection_status")
                    or "encoded_no_indicator_match"
                )
                entries.append(
                    {
                        "source": source,
                        "path": path,
                        "evidence_type": "encoded_payload_metadata",
                        "value_included": False,
                        "evidence_bytes": len(evidence_bytes),
                        "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
                        "content_inspection_status": content_status,
                        "security_relevance": "runtime_correlated",
                        "selection_reason": "opaque_payload_correlated_with_rasp_runtime",
                        "indicator_categories": [],
                        "trust": "untrusted_external_telemetry",
                        **public_profile,
                        **correlation_metadata(),
                    }
                )
                inspection_states.add(content_status)
                relevance_states.add("runtime_correlated")
                return

            projected_text = (
                inspection_text
                if explicit_indicators and isinstance(inspection_text, str)
                else raw_text
            )
            context_trimmed = False
            if not direct:
                projected_text, context_trimmed = self._rasp_attack_indicator_excerpt(raw_text)
                if isinstance(inspection_text, str):
                    projected_text, context_trimmed = self._rasp_attack_indicator_excerpt(
                        inspection_text
                    )
            redacted_value = self.policy.redact({"selected_value": projected_text}).get("selected_value", "")
            redacted_text = str(redacted_value)
            evidence_bytes = redacted_text.encode("utf-8", errors="replace")
            safe_value, value_truncated = self._truncate_rasp_evidence_text(
                redacted_text,
                _RASP_EVIDENCE_MAX_VALUE_BYTES,
            )
            entry = {
                "source": source,
                "path": path,
                "value": safe_value,
                "evidence_bytes": len(evidence_bytes),
                "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
                "value_truncated": value_truncated or context_trimmed,
                "context_trimmed_to_indicator": context_trimmed,
                "sensitive_content_redacted": redacted_text != projected_text,
                "indicator_categories": explicit_indicators,
                "trust": "untrusted_external_telemetry",
            }
            entry_inspection_status = (
                "decoded_indicator_match"
                if isinstance(inspection_text, str) and explicit_indicators
                else "indicator_matched"
                if explicit_indicators
                else "allowlisted_field"
            )
            entry_relevance = (
                "content_indicator_matched"
                if explicit_indicators
                else "rule_relevant_field"
            )
            if isinstance(encoded_profile, dict):
                entry.update(
                    {
                        key: item
                        for key, item in encoded_profile.items()
                        if not str(key).startswith("_")
                        and key != "content_inspection_status"
                    }
                )
            entries.append(entry)
            inspection_states.add(entry_inspection_status)
            relevance_states.add(entry_relevance)

        walk(decoded, "$", 0)
        metadata_only = bool(entries) and all(
            entry.get("evidence_type") == "encoded_payload_metadata"
            for entry in entries
        )
        if metadata_only:
            selection_status = (
                "selected_by_runtime_correlation_with_truncation"
                if projection_truncated
                else "selected_by_runtime_correlation"
            )
        elif entries:
            selection_status = (
                "selected_with_truncation" if projection_truncated else "selected"
            )
        else:
            selection_status = "truncated" if projection_truncated else "no_rule_match"
        if "decoded_indicator_match" in inspection_states:
            content_inspection_status = "decoded_indicator_match"
        elif "indicator_matched" in inspection_states:
            content_inspection_status = "indicator_matched"
        elif "allowlisted_field" in inspection_states:
            content_inspection_status = "allowlisted_field"
        elif "opaque_encoded" in inspection_states:
            content_inspection_status = "opaque_encoded"
        elif inspection_states:
            content_inspection_status = sorted(inspection_states)[0]
        else:
            content_inspection_status = (
                "truncated_before_match" if projection_truncated else "no_indicator_match"
            )
        if "runtime_correlated" in relevance_states and len(relevance_states) > 1:
            security_relevance = "runtime_correlated_and_content_matched"
        elif "runtime_correlated" in relevance_states:
            security_relevance = "runtime_correlated"
        elif "content_indicator_matched" in relevance_states:
            security_relevance = "content_indicator_matched"
        elif "rule_relevant_field" in relevance_states:
            security_relevance = "rule_relevant_field"
        else:
            security_relevance = "unknown"
        result = {
            "policy": "rule_fields_indicators_and_runtime_correlation",
            "trust": "untrusted_external_telemetry",
            "entries": entries,
            "entry_count": len(entries),
            "truncated": projection_truncated,
            "selection_status": selection_status,
            "limits": {
                "max_entries": _RASP_EVIDENCE_MAX_ENTRIES,
                "max_depth": _RASP_EVIDENCE_MAX_DEPTH,
                "max_nodes": _RASP_EVIDENCE_MAX_NODES,
                "max_value_bytes": _RASP_EVIDENCE_MAX_VALUE_BYTES,
            },
        }
        encoded_entries_present = any(
            entry.get("evidence_type") == "encoded_payload_metadata"
            or entry.get("encoding") in {"base64", "base64url"}
            for entry in entries
        )
        if source.startswith("request_") and (
            encoded_entries_present or encoded_candidate_seen
        ):
            result["content_inspection_status"] = content_inspection_status
            result["security_relevance"] = security_relevance
        if unrecognized_security_fields:
            result["unrecognized_security_fields"] = sorted(
                unrecognized_security_fields
            )
        return result

    def _decode_rasp_evidence_value(self, value: Any, *, allow_form: bool) -> Any:
        if not isinstance(value, str):
            return value
        text = value.strip()
        if not text:
            return value
        if len(text) <= _RASP_CONTEXT_MAX_TEXT and text[:1] in {"{", "["}:
            try:
                parsed = loads_bounded_json(text)
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                return parsed
        if allow_form and len(text) <= _RASP_CONTEXT_MAX_TEXT:
            multipart = self._decode_rasp_multipart_value(text)
            if multipart:
                return multipart
        if allow_form and len(text) <= _RASP_CONTEXT_MAX_TEXT and "=" in text:
            try:
                pairs = parse_qsl(
                    text,
                    keep_blank_values=True,
                    strict_parsing=False,
                    max_num_fields=_RASP_EVIDENCE_MAX_NODES,
                )
            except ValueError:
                return value
            if pairs:
                parsed_form: dict[str, Any] = {}
                for key, item in pairs:
                    if key in parsed_form:
                        current = parsed_form[key]
                        parsed_form[key] = [*current, item] if isinstance(current, list) else [current, item]
                    else:
                        parsed_form[key] = item
                return parsed_form
        return value

    @staticmethod
    def _decode_rasp_multipart_value(value: str) -> dict[str, Any] | None:
        """Parse bounded text-only multipart fields without invoking MIME code.

        RASP vendors often place the already-captured request body under a
        ``rasp_raw_data`` wrapper.  We only recover field boundaries and never
        interpret file names, content types or nested MIME structures.
        """
        text = str(value or "")
        if "content-disposition:" not in text.casefold():
            return None
        lines = text.splitlines()
        if not lines:
            return None
        delimiter = lines[0].strip()
        if not delimiter.startswith("--") or not 4 <= len(delimiter) <= 200:
            return None
        parsed: dict[str, Any] = {}
        for raw_part in text.split(delimiter)[1:_RASP_EVIDENCE_MAX_NODES + 1]:
            part = raw_part.strip("\r\n")
            if not part or part == "--":
                continue
            if part.endswith("--"):
                part = part[:-2].rstrip("\r\n")
            if "\r\n\r\n" in part:
                header_text, body = part.split("\r\n\r\n", 1)
            elif "\n\n" in part:
                header_text, body = part.split("\n\n", 1)
            else:
                continue
            name_match = re.search(
                r"(?im)^content-disposition:[^\r\n]*\bname=(?:\"([^\"]{1,128})\"|([^;\r\n]{1,128}))",
                header_text,
            )
            if not name_match:
                continue
            name = (name_match.group(1) or name_match.group(2) or "").strip()
            if not name:
                continue
            body = body.rstrip("\r\n")
            if name in parsed:
                current = parsed[name]
                parsed[name] = [*current, body] if isinstance(current, list) else [current, body]
            else:
                parsed[name] = body
        return parsed or None

    def _inspect_rasp_encoded_value(self, value: str) -> dict[str, Any] | None:
        """Decode one bounded Base64 layer and safely inspect its format.

        This is transport unwrapping, not decryption.  Opaque decoded bytes are
        represented only by metadata; decoded text is returned internally for
        the existing deterministic indicator matcher.
        """
        text = str(value or "").strip()
        compact = re.sub(r"\s+", "", text)
        encoded_bytes = compact.encode("ascii", errors="ignore")
        if (
            len(compact) < 16
            or len(compact) > _RASP_BASE64_MAX_ENCODED_BYTES
            or len(compact) % 4 != 0
            or len(encoded_bytes) != len(compact)
        ):
            return None
        if re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
            encoding = "base64"
            altchars = None
        elif re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", compact):
            encoding = "base64url"
            altchars = b"-_"
        else:
            return None
        try:
            decoded = base64.b64decode(
                encoded_bytes,
                altchars=altchars,
                validate=True,
            )
        except (binascii.Error, ValueError):
            return None
        if not decoded or len(decoded) > _RASP_BASE64_MAX_DECODED_BYTES:
            return None

        inspected = decoded
        compression_status = "not_compressed"
        if decoded.startswith(b"\x1f\x8b"):
            decompressed, compression_status = self._bounded_rasp_gzip_decompress(decoded)
            if decompressed is not None:
                inspected = decompressed

        content_format, inspection_text, printable_ratio = self._classify_rasp_decoded_bytes(
            inspected
        )
        entropy = self._rasp_byte_entropy(inspected)
        if inspection_text is not None:
            decoded_indicators = sorted(
                set(self._rasp_indicator_categories(inspection_text))
                & _RASP_EXPLICIT_ATTACK_INDICATORS
            )
            content_status = (
                "decoded_indicator_match"
                if decoded_indicators
                else "decoded_no_indicator_match"
            )
        elif content_format == "opaque_binary":
            content_status = "opaque_encoded"
        else:
            content_status = "decoded_known_binary_format"

        return {
            "encoding": encoding,
            "encoded_chars": len(compact),
            "base64_decoded_bytes": len(decoded),
            "inspected_bytes": len(inspected),
            "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
            "decoded_entropy_bits_per_byte": round(entropy, 4),
            "decoded_printable_ratio": round(printable_ratio, 4),
            "content_format": content_format,
            "compression_status": compression_status,
            "content_inspection_status": content_status,
            "_inspection_text": inspection_text,
        }

    @staticmethod
    def _bounded_rasp_gzip_decompress(
        value: bytes,
    ) -> tuple[bytes | None, str]:
        try:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            output = decompressor.decompress(
                value,
                _RASP_DECOMPRESSED_MAX_BYTES + 1,
            )
            if (
                len(output) > _RASP_DECOMPRESSED_MAX_BYTES
                or decompressor.unconsumed_tail
                or not decompressor.eof
            ):
                return None, "gzip_limit_exceeded"
            remaining = _RASP_DECOMPRESSED_MAX_BYTES + 1 - len(output)
            output += decompressor.flush(remaining)
            if len(output) > _RASP_DECOMPRESSED_MAX_BYTES:
                return None, "gzip_limit_exceeded"
            return output, "gzip_decompressed"
        except (ValueError, zlib.error):
            return None, "gzip_invalid"

    @staticmethod
    def _classify_rasp_decoded_bytes(
        value: bytes,
    ) -> tuple[str, str | None, float]:
        if not value:
            return "empty", None, 0.0
        printable_ratio = sum(
            byte in (9, 10, 13) or 32 <= byte < 127
            for byte in value
        ) / len(value)
        if value.startswith(b"\xac\xed\x00\x05"):
            return "java_serialization_stream", None, printable_ratio
        if value.startswith(b"PK\x03\x04"):
            return "zip_archive", None, printable_ratio
        if value.startswith(b"\x1f\x8b"):
            return "gzip_stream", None, printable_ratio
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            return "opaque_binary", None, printable_ratio
        if printable_ratio < 0.85:
            return "opaque_binary", None, printable_ratio
        stripped = text.lstrip()
        if stripped.startswith(("{", "[")):
            if len(stripped) <= _RASP_CONTEXT_MAX_TEXT:
                try:
                    parsed = loads_bounded_json(stripped)
                except (TypeError, ValueError, json.JSONDecodeError):
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    return "json_text", text, printable_ratio
        if stripped.startswith("<"):
            return "xml_text", text, printable_ratio
        return "utf8_text", text, printable_ratio

    @staticmethod
    def _rasp_byte_entropy(value: bytes) -> float:
        if not value:
            return 0.0
        size = len(value)
        return -sum(
            (count / size) * math.log2(count / size)
            for count in Counter(value).values()
        )

    @staticmethod
    def _truncate_rasp_evidence_text(value: str, max_bytes: int) -> tuple[str, bool]:
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) <= max_bytes:
            return value, False
        marker = "...[TRUNCATED]"
        available = max(0, max_bytes - len(marker.encode("utf-8")))
        prefix = encoded[:available].decode("utf-8", errors="ignore")
        return f"{prefix}{marker}", True

    def _rasp_indicator_categories(self, value: Any) -> list[str]:
        found: set[str] = set()
        for text in self._rasp_text_leaves(value):
            for name, pattern in _RASP_INDICATORS:
                if pattern.search(text):
                    found.add(name)
        return sorted(found)

    @staticmethod
    def _rasp_attack_indicator_excerpt(value: str) -> tuple[str, bool]:
        matches = []
        for name, pattern in _RASP_INDICATORS:
            if name not in _RASP_EXPLICIT_ATTACK_INDICATORS:
                continue
            match = pattern.search(value)
            if match:
                matches.append(match)
        if not matches:
            return value, False
        start = min(match.start() for match in matches)
        end = min(len(value), start + _RASP_EVIDENCE_MAX_VALUE_BYTES * 2)
        return value[start:end], start > 0 or end < len(value)

    def _rasp_text_leaves(self, value: Any, depth: int = 0) -> list[str]:
        if depth > 8:
            return []
        if isinstance(value, str):
            return [value[:_RASP_CONTEXT_MAX_TEXT]]
        if isinstance(value, dict):
            leaves: list[str] = []
            for item in list(value.values())[:_RASP_CONTEXT_MAX_LEAVES]:
                leaves.extend(self._rasp_text_leaves(item, depth + 1))
                if len(leaves) >= _RASP_CONTEXT_MAX_LEAVES:
                    break
            return leaves[:_RASP_CONTEXT_MAX_LEAVES]
        if isinstance(value, list):
            leaves = []
            for item in value[:_RASP_CONTEXT_MAX_LEAVES]:
                leaves.extend(self._rasp_text_leaves(item, depth + 1))
                if len(leaves) >= _RASP_CONTEXT_MAX_LEAVES:
                    break
            return leaves[:_RASP_CONTEXT_MAX_LEAVES]
        return []

    @staticmethod
    def _canonical_rasp_field_name(value: Any) -> str:
        text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value).strip())
        return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:64]

    @staticmethod
    def _safe_rasp_label(value: Any, limit: int) -> str:
        return str(value or "").strip()[:limit]

    @staticmethod
    def _rasp_serialized(value: Any) -> str:
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            return repr(value)

    def _derive_rasp_sink(self, stacktrace: Any) -> str:
        frames = self._stack_frames(stacktrace)
        if not frames:
            return ""
        high_risk_sink_needles = [
            "java.lang.system.loadlibrary",
            "java.lang.system.load",
            "java.lang.runtime.loadlibrary",
            "java.lang.runtime.load",
            "runtime.loadlibrary",
            "runtime.load",
            "java.io.file.listfiles",
            "java.io.file.list",
            "java.io.file.delete",
            "java.io.file.renameto",
        ]
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
            if any(needle in normalized for needle in high_risk_sink_needles):
                return self._frame_symbol(frame)
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

    def _build_adapter_evidence(
        self,
        profile: MappingProfile,
        log: dict[str, Any],
        *,
        product: str,
        rasp_runtime_context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        evidence = []
        product = str(product or "").strip().lower()
        rasp_compound_transforms = {
            "hook_data": ("rasp_hook_data_summary", self._summarize_rasp_hook_data),
            "request_context": (
                "rasp_request_context",
                lambda value: self._summarize_rasp_request_context(
                    value,
                    runtime_context=rasp_runtime_context,
                ),
            ),
            "request_parameters": (
                "rasp_request_parameter_summary",
                lambda value: self._summarize_rasp_request_parameters(
                    value,
                    runtime_context=rasp_runtime_context,
                ),
            ),
            "rasp_items_context": ("rasp_items_context", self._summarize_rasp_items_context),
            "rasp_evidence_integrity": ("rasp_evidence_integrity", self._summarize_rasp_evidence_integrity),
        }
        for idx, item in enumerate(profile.evidence_fields):
            if not isinstance(item, dict):
                continue
            item_type = str(item.get("type") or "mapped_field").strip().lower()
            evidence_mapping = item.get("path")
            if product == "rasp" and not self._mapping_is_unambiguous_path_only(evidence_mapping):
                continue
            value = self._resolve_mapping(
                evidence_mapping,
                log,
                rasp_runtime_context=rasp_runtime_context,
            )
            if value in ("", None):
                continue
            if product == "rasp":
                compound_transform = rasp_compound_transforms.get(item_type)
                if compound_transform is None:
                    if not self._rasp_scalar_evidence_mapping_allowed(item_type, item.get("path")):
                        # A configurable profile cannot reflect an arbitrary raw
                        # path merely by labelling it rule/sink/stack evidence.
                        continue
                    value = self.policy.redact(value)
                else:
                    transform_name, transform = compound_transform
                    if not self._mapping_uses_only_transform(item.get("path"), transform_name):
                        # Never trust the external value's shape as proof that it
                        # was projected. Missing/alternate transforms are rebuilt
                        # through the system-owned projector unconditionally.
                        value = transform(value)
                if value in ("", None):
                    continue
            evidence.append(
                {
                    "ref": f"mapping:{profile.profile_id}:{idx}",
                    "source": profile.profile_id,
                    "type": item_type,
                    "value": value,
                    "why_it_matters": str(item.get("why_it_matters") or item.get("label") or "日志适配配置提取的证据字段。"),
                }
            )
        return evidence

    def _mapping_uses_only_transform(self, mapping: Any, expected: str) -> bool:
        if isinstance(mapping, list):
            return bool(mapping) and all(
                self._mapping_uses_only_transform(item, expected) for item in mapping
            )
        specs = self._mapping_specs(mapping)
        return len(specs) == 1 and next(iter(specs))[1] == expected

    def _mapping_is_unambiguous_path_only(self, mapping: Any) -> bool:
        if isinstance(mapping, list):
            return bool(mapping) and all(
                self._mapping_is_unambiguous_path_only(item) for item in mapping
            )
        return len(self._mapping_specs(mapping)) == 1

    def _filter_mapping_to_reference(self, mapping: Any, reference: Any) -> Any:
        allowed = self._mapping_specs(reference)
        if not allowed:
            return None
        if isinstance(mapping, list):
            filtered = [
                item
                for item in (
                    self._filter_mapping_to_reference(candidate, reference)
                    for candidate in mapping
                )
                if item is not None
            ]
            return filtered or None
        specs = self._mapping_specs(mapping)
        return mapping if specs and specs.issubset(allowed) else None

    def _mapping_specs(self, mapping: Any) -> set[tuple[str, str]]:
        if isinstance(mapping, list):
            specs: set[tuple[str, str]] = set()
            for item in mapping:
                specs.update(self._mapping_specs(item))
            return specs
        if isinstance(mapping, dict) and mapping.get("path"):
            # Avoid parser differentials: _resolve_mapping gives ``literal``
            # precedence, so a model-visible path mapping must use a strict and
            # unambiguous grammar before its path can be allowlisted.
            if "literal" in mapping or not set(mapping).issubset({"path", "transform"}):
                return set()
            return {(str(mapping["path"]), str(mapping.get("transform") or ""))}
        if isinstance(mapping, str) and (mapping.startswith("$.") or mapping == "$"):
            return {(mapping, "")}
        return set()

    def _rasp_scalar_evidence_mapping_allowed(self, item_type: str, mapping: Any) -> bool:
        if isinstance(mapping, list):
            return bool(mapping) and all(
                self._rasp_scalar_evidence_mapping_allowed(item_type, item) for item in mapping
            )
        specs = self._mapping_specs(mapping)
        if len(specs) != 1:
            return False
        path, transform = next(iter(specs))
        if item_type == "sink" and transform == "rasp_sink_from_stacktrace":
            return path == "$.items[0].stacktrace"
        if transform:
            return False
        allowed_paths = {
            "action": {"$.rasp.action", "$.items[0].intercept_state"},
            "rule_id": {"$.rule.id", "$.items[0].rule_id"},
            "sink": {"$.sink"},
            "stack_trace": {"$.stacktrace", "$.items[0].stacktrace"},
        }
        return path in allowed_paths.get(item_type, set())

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
