from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
from typing import Any


OPERATIONAL_TEST_MARKER_FIELD = "_defensive_ai_operational_test"
_OPERATIONAL_TEST_MARKER_VERSION = "v1"


def _identity_material(alert_id: object, product: object, timestamp: object) -> bytes:
    identity = {
        "alert_id": str(alert_id or "").strip(),
        "product": str(product or "").strip().lower(),
        "timestamp": str(timestamp or "").strip(),
        "version": _OPERATIONAL_TEST_MARKER_VERSION,
    }
    return json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_operational_test_marker(
    alert_id: object,
    product: object,
    timestamp: object,
    secret: str,
) -> dict[str, str]:
    """Sign one adapted Syslog identity without exposing the signing secret."""
    signature = hmac.new(
        str(secret or "").encode("utf-8"),
        _identity_material(alert_id, product, timestamp),
        hashlib.sha256,
    ).hexdigest()
    return {"version": _OPERATIONAL_TEST_MARKER_VERSION, "signature": signature}


def verify_operational_test_marker(
    marker: object,
    *,
    alert_id: object,
    product: object,
    timestamp: object,
    secret: str,
) -> bool:
    if not isinstance(marker, dict):
        return False
    if str(marker.get("version") or "") != _OPERATIONAL_TEST_MARKER_VERSION:
        return False
    signature = str(marker.get("signature") or "").strip().lower()
    if len(signature) != 64 or any(character not in "0123456789abcdef" for character in signature):
        return False
    expected = build_operational_test_marker(alert_id, product, timestamp, secret)["signature"]
    return hmac.compare_digest(signature, expected)


def extract_operational_test_marker(payload: object) -> object | None:
    """Find a unique marker in a bounded inbound JSON tree.

    Collector transforms may move a native log under ``log`` or
    ``payload.original_log``. Equivalent copies are accepted, while conflicting
    markers are rejected to avoid ambiguous trust decisions.
    """
    markers: list[object] = []
    stack = [payload]
    visited: set[int] = set()
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if id(node) in visited:
                continue
            visited.add(id(node))
            for key, value in node.items():
                if str(key).casefold() == OPERATIONAL_TEST_MARKER_FIELD:
                    markers.append(value)
                elif isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            if id(node) in visited:
                continue
            visited.add(id(node))
            stack.extend(item for item in node if isinstance(item, (dict, list)))
    if not markers:
        return None
    rendered = {
        json.dumps(marker, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        for marker in markers
    }
    if len(rendered) != 1:
        raise ValueError("conflicting operational test markers")
    return markers[0]


def strip_operational_test_markers(payload: object) -> None:
    """Remove reserved markers recursively before evidence normalization."""
    stack = [payload]
    visited: set[int] = set()
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if id(node) in visited:
                continue
            visited.add(id(node))
            for key in list(node):
                if str(key).casefold() == OPERATIONAL_TEST_MARKER_FIELD:
                    node.pop(key, None)
                    continue
                value = node.get(key)
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            if id(node) in visited:
                continue
            visited.add(id(node))
            stack.extend(item for item in node if isinstance(item, (dict, list)))


def trusted_syslog_test_source(route: object) -> bool:
    """Accept only server-owned routes whose transport peer is loopback."""
    if not isinstance(route, dict):
        return False
    if str(route.get("route_reason") or "").strip().lower() not in {
        "port_profile",
        "port_standard",
    }:
        return False
    collector = str(route.get("collector") or "").strip().lower()
    if collector == "vector":
        source = str(route.get("source_ip") or "").strip()
    elif collector == "syslog-port-router":
        source = str(route.get("hostname") or "").strip()
    else:
        return False
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback
