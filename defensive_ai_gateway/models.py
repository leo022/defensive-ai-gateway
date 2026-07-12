from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class RawAlert:
    source: str
    product: str
    event_type: str
    severity: str
    timestamp: str
    payload: dict[str, Any]
    alert_id: str = field(default_factory=lambda: new_id("alert"))


@dataclass
class NormalizedEvent:
    event_id: str
    source: str
    product: str
    event_type: str
    severity: str
    timestamp: str
    entities: dict[str, Any]
    evidence: list[dict[str, Any]]
    sensitivity_tags: list[str]
    raw_ref: str


@dataclass
class RecommendedAction:
    action: str
    mode: str
    rationale: str
    rollback: str = ""


@dataclass
class ValidationFinding:
    code: str
    severity: str
    message: str
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    validation_id: str
    case_id: str
    event_id: str
    status: str
    validator: str
    validator_version: str
    findings: list[ValidationFinding]
    checks: dict[str, bool]
    created_at_ms: int = field(default_factory=now_ms)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApprovalRequest:
    approval_id: str
    case_id: str
    event_id: str
    action: str
    rationale: str
    rollback: str
    mode: str = "approve_required"
    status: str = "pending"
    requested_by: str = "response-advisor"
    created_at_ms: int = field(default_factory=now_ms)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AgentResult:
    case_id: str
    agent: str
    classification: str
    confidence: float
    severity: str
    summary: str
    evidence: list[dict[str, Any]]
    missing_evidence: list[str]
    recommended_actions: list[RecommendedAction]
    dashboard_cards: list[dict[str, str]]
    explanation: dict[str, Any] = field(default_factory=dict)
    created_at_ms: int = field(default_factory=now_ms)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseRecord:
    case_id: str
    status: str
    severity: str
    classification: str
    confidence: float
    summary: str
    product: str
    created_at_ms: int
    updated_at_ms: int
