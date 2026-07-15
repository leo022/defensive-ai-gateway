from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

from .log_adapter import DEFAULT_SEVERITY_MAP, SUPPORTED_PRODUCTS
from .models import new_id


@dataclass
class RoutedSyslog:
    product: str
    port: int
    profile_id: str
    payload: dict[str, Any]
    route_reason: str
    warnings: list[str]
    envelope: dict[str, Any] = field(default_factory=dict)


def _nested_get(data: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        node: Any = data
        ok = True
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                ok = False
                break
        if ok and node not in ("", None):
            return node
    return None


def _parse_message(message: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(message, dict):
        return message
    text = message.decode("utf-8", errors="replace") if isinstance(message, bytes) else str(message)
    text = text.strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {"message": value}
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if 0 <= start < end:
        try:
            value = json.loads(text[start : end + 1])
            return value if isinstance(value, dict) else {"message": value}
        except json.JSONDecodeError:
            pass
    return {"message": text}


def _raw_message(message: bytes | str | dict[str, Any]) -> str:
    if isinstance(message, bytes):
        return message.decode("utf-8", errors="replace")
    if isinstance(message, str):
        return message
    return json.dumps(message, ensure_ascii=False, separators=(",", ":"), default=str)


def _message_format(message: bytes | str | dict[str, Any], structured: dict[str, Any]) -> str:
    if isinstance(message, dict):
        return "object"
    text = _raw_message(message).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        return "json"
    if set(structured) == {"message"} and structured.get("message") == text:
        return "text"
    return "embedded_json"


class SyslogPortRouter:
    """Port-first syslog classifier used by the collector and demo simulator."""

    def __init__(self, product_ports: dict[str, int], gateway_profiles: dict[str, str] | None = None):
        self.product_ports = {str(product).lower(): int(port) for product, port in product_ports.items()}
        self.port_products = {port: product for product, port in self.product_ports.items() if product in SUPPORTED_PRODUCTS}
        self.gateway_profiles = {str(product).lower(): str(profile) for product, profile in (gateway_profiles or {}).items()}

    def route(
        self,
        port: int,
        message: bytes | str | dict[str, Any],
        *,
        hostname: str = "",
        appname: str = "",
        protocol: str = "",
    ) -> RoutedSyslog:
        structured = _parse_message(message)
        product = self.port_products.get(int(port))
        warnings: list[str] = []
        if not product:
            raise ValueError(f"unmapped syslog destination port: {port}")

        declared = str(
            _nested_get(structured, "product", "event.product", "device.type", "source.product") or appname or ""
        ).lower()
        if declared in SUPPORTED_PRODUCTS and declared != product:
            warnings.append(f"declared_product_mismatch:{declared}")

        profile_id = self.gateway_profiles.get(product, "")
        route_reason = "port_profile" if profile_id else "port_standard"
        envelope = self._route_meta(
            port,
            product,
            hostname,
            appname,
            warnings,
            raw_message=_raw_message(message),
            message_format=_message_format(message, structured),
            protocol=protocol,
            route_reason=route_reason,
        )
        if profile_id:
            profiled_log = dict(structured)
            # The destination port is the trusted routing contract. Preserve a
            # conflicting declaration in warnings/envelope, but ensure profile
            # mapping cannot route the event back to the spoofed product.
            profiled_log["product"] = product
            profiled_log["_syslog_envelope"] = envelope
            payload = {
                "profile_id": profile_id,
                "log": profiled_log,
                "syslog_route": envelope,
            }
            return RoutedSyslog(product, int(port), profile_id, payload, route_reason, warnings, envelope)

        payload = self._standard_payload(structured, product, appname, envelope)
        return RoutedSyslog(product, int(port), "", payload, route_reason, warnings, envelope)

    def _route_meta(
        self,
        port: int,
        product: str,
        hostname: str,
        appname: str,
        warnings: list[str],
        *,
        raw_message: str,
        message_format: str,
        protocol: str,
        route_reason: str,
    ) -> dict[str, Any]:
        return {
            "collector": "syslog-port-router",
            "destination_port": int(port),
            "product": product,
            "hostname": hostname,
            "appname": appname,
            "protocol": str(protocol).lower(),
            "route_reason": route_reason,
            "message_format": message_format,
            "raw_message": raw_message,
            "received_at_ms": int(time.time() * 1000),
            "received_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "warnings": list(warnings),
        }

    def _standard_payload(
        self,
        structured: dict[str, Any],
        product: str,
        appname: str,
        envelope: dict[str, Any],
    ) -> dict[str, Any]:
        alert_id = _nested_get(structured, "alert_id", "alert.id", "metadata.id", "event.id", "id")
        source = (
            _nested_get(structured, "source", "device.name", "device.sensor", "device.vendor")
            or appname
            or envelope.get("hostname")
            or "syslog"
        )
        severity = str(_nested_get(structured, "severity", "risk.level", "priority", "level") or "medium").lower()
        severity = DEFAULT_SEVERITY_MAP.get(severity, severity)
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "medium"
        timestamp = str(_nested_get(structured, "timestamp", "event.time", "event_time", "time", "@timestamp") or "")
        payload = dict(structured)
        payload["syslog_route"] = envelope
        payload["original_log"] = structured
        return {
            "alert_id": str(alert_id or new_id(f"{product}_syslog")),
            "source": str(source),
            "product": product,
            "event_type": str(_nested_get(structured, "event_type", "event.type", "rule.name", "type") or "syslog_event"),
            "severity": severity,
            "timestamp": timestamp,
            "payload": payload,
        }
