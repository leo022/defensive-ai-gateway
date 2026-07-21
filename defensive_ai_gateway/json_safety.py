"""Resource bounds for untrusted JSON accepted by any ingestion transport."""

from __future__ import annotations

import json
from typing import Any


MAX_JSON_NESTING = 64
MAX_JSON_NODES = 20_000


def validate_json_nesting(text: str) -> None:
    """Reject excessively nested JSON before ``json.loads`` recurses into it."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise ValueError("JSON nesting exceeds the allowed limit")
        elif char in "}]":
            depth -= 1


def validate_json_node_budget(value: object) -> None:
    """Limit decoded JSON values before they reach recursive processing paths."""
    nodes = 0
    pending = [value]
    while pending:
        current = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("JSON value count exceeds the allowed limit")
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def loads_bounded_json(text: str) -> Any:
    """Decode untrusted JSON only after enforcing structural limits."""
    validate_json_nesting(text)
    value = json.loads(text)
    validate_json_node_budget(value)
    return value
