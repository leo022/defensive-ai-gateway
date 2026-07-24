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
    # Set only by a trusted server-side demo/harness path. Inbound payloads must
    # never be allowed to set this flag themselves: it controls whether sample
    # ground-truth annotations may participate in analysis.
    trusted_sample: bool = False


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
class ValidationEvidenceClue:
    """A bounded, redacted location for a validation finding in external input."""

    evidence_ref: str
    field_path: str
    excerpt: str


@dataclass
class ValidationFinding:
    code: str
    severity: str
    message: str
    evidence_refs: list[str] = field(default_factory=list)
    evidence_clues: list[ValidationEvidenceClue] = field(default_factory=list)


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

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ValidationResult":
        findings = [
            item
            if isinstance(item, ValidationFinding)
            else ValidationFinding(
                code=str(item.get("code", "")),
                severity=str(item.get("severity", "")),
                message=str(item.get("message", "")),
                evidence_refs=[str(ref) for ref in item.get("evidence_refs", [])],
                evidence_clues=[
                    clue
                    if isinstance(clue, ValidationEvidenceClue)
                    else ValidationEvidenceClue(
                        evidence_ref=str(clue.get("evidence_ref", "")),
                        field_path=str(clue.get("field_path", "")),
                        excerpt=str(clue.get("excerpt", "")),
                    )
                    for clue in item.get("evidence_clues", [])
                    if isinstance(clue, (ValidationEvidenceClue, dict))
                ],
            )
            for item in payload.get("findings", [])
            if isinstance(item, (ValidationFinding, dict))
        ]
        return cls(
            validation_id=str(payload["validation_id"]),
            case_id=str(payload["case_id"]),
            event_id=str(payload["event_id"]),
            status=str(payload["status"]),
            validator=str(payload["validator"]),
            validator_version=str(payload["validator_version"]),
            findings=findings,
            checks={str(key): bool(value) for key, value in dict(payload.get("checks", {})).items()},
            created_at_ms=int(payload.get("created_at_ms", 0)),
        )


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
    required_approvals: int = 1
    validation_id: str = ""
    review_resolution_id: str = ""
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

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AgentResult":
        actions = [
            item
            if isinstance(item, RecommendedAction)
            else RecommendedAction(
                action=str(item.get("action", "")),
                mode=str(item.get("mode", "observe")),
                rationale=str(item.get("rationale", "")),
                rollback=str(item.get("rollback", "")),
            )
            for item in payload.get("recommended_actions", [])
            if isinstance(item, (RecommendedAction, dict))
        ]
        return cls(
            case_id=str(payload["case_id"]),
            agent=str(payload["agent"]),
            classification=str(payload["classification"]),
            confidence=float(payload["confidence"]),
            severity=str(payload["severity"]),
            summary=str(payload["summary"]),
            evidence=list(payload.get("evidence", [])),
            missing_evidence=[str(item) for item in payload.get("missing_evidence", [])],
            recommended_actions=actions,
            dashboard_cards=list(payload.get("dashboard_cards", [])),
            explanation=dict(payload.get("explanation", {})),
            created_at_ms=int(payload.get("created_at_ms", 0)),
        )


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
