from __future__ import annotations

import json
from dataclasses import dataclass
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


class SyslogPortRouter:
    """Port-first syslog classifier used by the collector and demo simulator."""

    def __init__(self, product_ports: dict[str, int], gateway_profiles: dict[str, str] | None = None):
        self.product_ports = {str(product).lower(): int(port) for product, port in product_ports.items()}
        self.port_products = {port: product for product, port in self.product_ports.items() if product in SUPPORTED_PRODUCTS}
        self.gateway_profiles = {str(product).lower(): str(profile) for product, profile in (gateway_profiles or {}).items()}

    def route(self, port: int, message: bytes | str | dict[str, Any], *, hostname: str = "", appname: str = "") -> RoutedSyslog:
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
        if profile_id:
            payload = {
                "profile_id": profile_id,
                "log": structured,
                "syslog_route": self._route_meta(port, product, hostname, appname, warnings),
            }
            return RoutedSyslog(product, int(port), profile_id, payload, "port_profile", warnings)

        payload = self._standard_payload(structured, port, product, hostname, appname, warnings)
        return RoutedSyslog(product, int(port), "", payload, "port_standard", warnings)

    def _route_meta(self, port: int, product: str, hostname: str, appname: str, warnings: list[str]) -> dict[str, Any]:
        return {
            "collector": "syslog-port-router",
            "destination_port": int(port),
            "product": product,
            "hostname": hostname,
            "appname": appname,
            "warnings": warnings,
        }

    def _standard_payload(
        self,
        structured: dict[str, Any],
        port: int,
        product: str,
        hostname: str,
        appname: str,
        warnings: list[str],
    ) -> dict[str, Any]:
        alert_id = _nested_get(structured, "alert_id", "alert.id", "metadata.id", "event.id", "id")
        source = _nested_get(structured, "source", "device.name", "device.sensor", "device.vendor") or appname or hostname or "syslog"
        severity = str(_nested_get(structured, "severity", "risk.level", "priority", "level") or "medium").lower()
        severity = DEFAULT_SEVERITY_MAP.get(severity, severity)
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "medium"
        timestamp = str(_nested_get(structured, "timestamp", "event.time", "event_time", "time", "@timestamp") or "")
        payload = dict(structured)
        payload["syslog_route"] = self._route_meta(port, product, hostname, appname, warnings)
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
