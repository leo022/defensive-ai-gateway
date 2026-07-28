from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .action_plan import ACTION_STAGE_ORDER, action_stage
from .models import NormalizedEvent, new_id, now_ms
from .response_automation import ACTION_BLOCK_IP, compile_response_action


PACK_SCHEMA_VERSION = "case-response-pack-v1"
PACK_GENERATOR = "deterministic-case-response-assembler-v1"
MAX_TIMELINE_ITEMS = 2_000
MAX_PACK_TIMELINE_ITEMS = 12
MAX_PLAYBOOK_STEPS = 12
MAX_EVIDENCE_REFS = 64
_TERMINAL_CASE_STATUSES = {"closed", "false_positive"}


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _bounded_text(value: Any, limit: int = 1_000) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 3)].rstrip()}..."


def _reported_time(value: Any, recorded_at_ms: int) -> tuple[int, str]:
    try:
        normalized = str(value or "").strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1_000), "reported"
    except (TypeError, ValueError, OverflowError):
        return int(recorded_at_ms), "ingest_fallback"


def _event_refs(event: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for item in event.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        ref = item.get("ref")
        if not ref and isinstance(item.get("value"), dict):
            ref = item["value"].get("ref")
        rendered = str(ref or "").strip()
        if rendered and rendered not in refs:
            refs.append(rendered)
            if len(refs) >= MAX_EVIDENCE_REFS:
                break
    if not refs and event.get("event_id"):
        refs.append(str(event["event_id"]))
    suffix_priority = {
        ":rule_id": 1,
        ":src_ip": 2,
        ":dst_ip": 3,
        ":uri": 4,
        ":method": 5,
        ":action": 6,
        ":status": 7,
    }
    indexed = list(enumerate(refs))
    indexed.sort(
        key=lambda item: (
            0
            if ":" not in item[1]
            else next(
                (
                    priority
                    for suffix, priority in suffix_priority.items()
                    if item[1].endswith(suffix)
                ),
                20,
            ),
            item[0],
        )
    )
    return [ref for _index, ref in indexed[:8]]


def _event_is_replay(event: dict[str, Any]) -> bool:
    if "__replay_" in str(event.get("event_id") or ""):
        return True
    return any(
        isinstance(item, dict) and item.get("type") == "analysis_replay"
        for item in event.get("evidence") or []
    )


def _event_context(event: dict[str, Any]) -> str:
    entities = event.get("entities") if isinstance(event.get("entities"), dict) else {}
    parts = []
    for label, key in (("source", "src_ip"), ("target", "host"), ("rule", "rule")):
        value = _bounded_text(entities.get(key), 160)
        if value:
            parts.append(f"{label}={value}")
    return " | ".join(parts[:3])


def _source_event_refs(
    events_by_id: dict[str, dict[str, Any]], event_id: Any
) -> list[str]:
    event = events_by_id.get(str(event_id or ""))
    return _event_refs(event) if event else []


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _timeline_page_item(row: dict[str, Any]) -> dict[str, Any]:
    kind = str(row.get("kind") or "")
    detail = _json_object(row.get("detail_json"))
    title = str(row.get("title") or "")
    state = str(row.get("state") or "")
    if kind == "security_event":
        context = _event_context({"entities": detail})
        if context:
            title = f"{title} | {context}"
    elif kind == "analysis":
        title = str(detail.get("summary") or title)
        state = str(detail.get("classification") or state)
    elif kind == "approval_request":
        action_type = detail.get("action_type") or detail.get("action")
        if action_type:
            title = f"Approval requested: {action_type}"
    elif kind == "governance":
        state = str(detail.get("status") or detail.get("decision") or state)

    evidence = _json_list(row.get("evidence_json"))
    refs = _event_refs(
        {
            "event_id": row.get("source_event_id"),
            "evidence": evidence,
        }
    )
    return {
        "entry_id": str(row.get("entry_id") or ""),
        "kind": kind,
        "source_id": str(row.get("source_id") or ""),
        "occurred_at_ms": int(row.get("occurred_at_ms") or 0),
        "recorded_at_ms": int(row.get("recorded_at_ms") or 0),
        "time_basis": str(row.get("time_basis") or "system"),
        "title": _bounded_text(title, 500),
        "state": state,
        "product": str(row.get("product") or ""),
        "actor": str(row.get("actor") or ""),
        "evidence_refs": refs,
        "evidence_hash": str(row.get("evidence_hash") or ""),
    }


def build_case_timeline(source: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a stable dual-clock timeline without model-authored timestamps."""
    items: list[dict[str, Any]] = []
    events = list(source.get("events") or [])
    events_by_id = {str(item.get("event_id") or ""): item for item in events}

    for event in events:
        recorded_at_ms = int(event.get("created_at_ms") or 0)
        replay = _event_is_replay(event)
        if replay:
            occurred_at_ms, time_basis = recorded_at_ms, "system"
            title = "Analysis replay created a new normalized evidence version"
            kind = "analysis_replay"
        else:
            occurred_at_ms, time_basis = _reported_time(
                event.get("timestamp"), recorded_at_ms
            )
            title = f"{str(event.get('product') or '').upper()} {event.get('event_type') or 'security event'}"
            context = _event_context(event)
            if context:
                title = f"{title} | {context}"
            kind = "security_event"
        items.append(
            {
                "entry_id": f"event:{event.get('event_id')}",
                "kind": kind,
                "source_id": str(event.get("event_id") or ""),
                "occurred_at_ms": occurred_at_ms,
                "recorded_at_ms": recorded_at_ms,
                "time_basis": time_basis,
                "title": _bounded_text(title, 500),
                "state": str(event.get("severity") or ""),
                "product": str(event.get("product") or ""),
                "actor": "",
                "evidence_refs": _event_refs(event),
            }
        )

    for run in source.get("agent_runs") or []:
        result = run.get("result") if isinstance(run.get("result"), dict) else {}
        recorded_at_ms = int(run.get("created_at_ms") or 0)
        items.append(
            {
                "entry_id": f"analysis:{run.get('run_id')}",
                "kind": "analysis",
                "source_id": str(run.get("run_id") or ""),
                "occurred_at_ms": recorded_at_ms,
                "recorded_at_ms": recorded_at_ms,
                "time_basis": "system",
                "title": _bounded_text(
                    result.get("summary") or "AI analysis completed", 500
                ),
                "state": str(result.get("classification") or ""),
                "product": str(run.get("product") or ""),
                "actor": str(run.get("agent") or ""),
                "evidence_refs": _source_event_refs(
                    events_by_id, run.get("event_id")
                ),
            }
        )

    for validation in source.get("validations") or []:
        recorded_at_ms = int(validation.get("created_at_ms") or 0)
        items.append(
            {
                "entry_id": f"validation:{validation.get('validation_id')}",
                "kind": "validation",
                "source_id": str(validation.get("validation_id") or ""),
                "occurred_at_ms": recorded_at_ms,
                "recorded_at_ms": recorded_at_ms,
                "time_basis": "system",
                "title": f"Validation gate: {validation.get('status') or 'unknown'}",
                "state": str(validation.get("status") or ""),
                "product": "",
                "actor": str(validation.get("validator") or ""),
                "evidence_refs": _source_event_refs(
                    events_by_id, validation.get("event_id")
                ),
            }
        )

    for approval in source.get("approvals") or []:
        created_at_ms = int(approval.get("created_at_ms") or 0)
        event_refs = _source_event_refs(events_by_id, approval.get("event_id"))
        action = approval.get("action") if isinstance(approval.get("action"), dict) else {}
        items.append(
            {
                "entry_id": f"approval-request:{approval.get('approval_id')}",
                "kind": "approval_request",
                "source_id": str(approval.get("approval_id") or ""),
                "occurred_at_ms": created_at_ms,
                "recorded_at_ms": created_at_ms,
                "time_basis": "system",
                "title": _bounded_text(
                    f"Approval requested: {action.get('action') or 'response action'}",
                    500,
                ),
                "state": "pending",
                "product": "",
                "actor": str(approval.get("requested_by") or ""),
                "evidence_refs": event_refs,
            }
        )
        updated_at_ms = int(approval.get("updated_at_ms") or created_at_ms)
        if approval.get("status") != "pending" and updated_at_ms >= created_at_ms:
            items.append(
                {
                    "entry_id": f"approval-decision:{approval.get('approval_id')}",
                    "kind": "approval_decision",
                    "source_id": str(approval.get("approval_id") or ""),
                    "occurred_at_ms": updated_at_ms,
                    "recorded_at_ms": updated_at_ms,
                    "time_basis": "system",
                    "title": f"Approval decision: {approval.get('status')}",
                    "state": str(approval.get("status") or ""),
                    "product": "",
                    "actor": str(approval.get("decided_by") or ""),
                    "evidence_refs": event_refs,
                }
            )

    approvals_by_id = {
        str(item.get("approval_id") or ""): item
        for item in source.get("approvals") or []
    }
    for vote in source.get("approval_votes") or []:
        approval = approvals_by_id.get(str(vote.get("approval_id") or ""), {})
        recorded_at_ms = int(vote.get("created_at_ms") or 0)
        items.append(
            {
                "entry_id": f"approval-vote:{vote.get('approval_id')}:{vote.get('actor')}",
                "kind": "approval_vote",
                "source_id": str(vote.get("approval_id") or ""),
                "occurred_at_ms": recorded_at_ms,
                "recorded_at_ms": recorded_at_ms,
                "time_basis": "system",
                "title": f"Approval vote: {vote.get('decision') or 'unknown'}",
                "state": str(vote.get("decision") or ""),
                "product": "",
                "actor": str(vote.get("actor") or ""),
                "evidence_refs": _source_event_refs(
                    events_by_id, approval.get("event_id")
                ),
            }
        )

    tasks_by_id: dict[str, dict[str, Any]] = {}
    for task in source.get("response_tasks") or []:
        task_id = str(task.get("task_id") or "")
        tasks_by_id[task_id] = task
        created_at_ms = int(task.get("created_at_ms") or 0)
        refs = _source_event_refs(events_by_id, task.get("event_id"))
        items.append(
            {
                "entry_id": f"response-task:{task_id}",
                "kind": "response_task",
                "source_id": task_id,
                "occurred_at_ms": created_at_ms,
                "recorded_at_ms": created_at_ms,
                "time_basis": "system",
                "title": f"Response task created: {task.get('action_type') or 'response action'}",
                "state": "created",
                "product": "",
                "actor": str(task.get("created_by") or ""),
                "evidence_refs": refs,
            }
        )
        updated_at_ms = int(task.get("updated_at_ms") or created_at_ms)
        if updated_at_ms > created_at_ms:
            items.append(
                {
                    "entry_id": f"response-task-state:{task_id}:{updated_at_ms}",
                    "kind": "response_task_state",
                    "source_id": task_id,
                    "occurred_at_ms": updated_at_ms,
                    "recorded_at_ms": updated_at_ms,
                    "time_basis": "system",
                    "title": f"Response task state: {task.get('status') or 'unknown'}",
                    "state": str(task.get("status") or ""),
                    "product": "",
                    "actor": "",
                    "evidence_refs": refs,
                }
            )

    for attempt in source.get("response_attempts") or []:
        task = tasks_by_id.get(str(attempt.get("task_id") or ""), {})
        recorded_at_ms = int(attempt.get("created_at_ms") or 0)
        items.append(
            {
                "entry_id": f"response-attempt:{attempt.get('attempt_id')}",
                "kind": "response_attempt",
                "source_id": str(attempt.get("attempt_id") or ""),
                "occurred_at_ms": recorded_at_ms,
                "recorded_at_ms": recorded_at_ms,
                "time_basis": "system",
                "title": f"Response {attempt.get('operation') or 'operation'}: {attempt.get('outcome') or 'unknown'}",
                "state": str(attempt.get("outcome") or ""),
                "product": "",
                "actor": "",
                "evidence_refs": _source_event_refs(
                    events_by_id, task.get("event_id")
                ),
            }
        )

    for audit in source.get("audit_events") or []:
        recorded_at_ms = int(audit.get("created_at_ms") or 0)
        detail = audit.get("detail") if isinstance(audit.get("detail"), dict) else {}
        items.append(
            {
                "entry_id": f"audit:{audit.get('audit_id')}",
                "kind": "governance",
                "source_id": str(audit.get("audit_id") or ""),
                "occurred_at_ms": recorded_at_ms,
                "recorded_at_ms": recorded_at_ms,
                "time_basis": "system",
                "title": _bounded_text(
                    f"Governance event: {audit.get('action') or 'case update'}",
                    500,
                ),
                "state": str(detail.get("status") or detail.get("decision") or ""),
                "product": "",
                "actor": str(audit.get("actor") or ""),
                "evidence_refs": _source_event_refs(
                    events_by_id, detail.get("event_id")
                ),
            }
        )

    kind_order = {
        "security_event": 10,
        "analysis_replay": 15,
        "analysis": 20,
        "validation": 30,
        "approval_request": 40,
        "approval_vote": 45,
        "approval_decision": 50,
        "response_task": 60,
        "response_attempt": 65,
        "response_task_state": 70,
        "governance": 80,
    }
    items.sort(
        key=lambda item: (
            int(item.get("occurred_at_ms") or 0),
            int(item.get("recorded_at_ms") or 0),
            kind_order.get(str(item.get("kind") or ""), 99),
            str(item.get("entry_id") or ""),
        )
    )
    return items[:MAX_TIMELINE_ITEMS]


def source_snapshot_hash(source: dict[str, Any]) -> str:
    case = source["case"]
    material = {
        "case": {
            key: case.get(key)
            for key in (
                "case_id",
                "status",
                "severity",
                "classification",
                "confidence",
                "summary",
                "updated_at_ms",
            )
        },
        "events": [
            {
                "event_id": item.get("event_id"),
                "evidence_hash": item.get("evidence_hash"),
                "event_at_ms": item.get("event_at_ms"),
                "created_at_ms": item.get("created_at_ms"),
            }
            for item in source.get("events") or []
        ],
        "agent_runs": [
            {
                "run_id": item.get("run_id"),
                "event_id": item.get("event_id"),
                "result_hash": _canonical_hash(item.get("result") or {}),
                "created_at_ms": item.get("created_at_ms"),
            }
            for item in source.get("agent_runs") or []
        ],
        "validations": [
            {
                "validation_id": item.get("validation_id"),
                "status": item.get("status"),
                "created_at_ms": item.get("created_at_ms"),
            }
            for item in source.get("validations") or []
        ],
        "approvals": [
            {
                "approval_id": item.get("approval_id"),
                "status": item.get("status"),
                "updated_at_ms": item.get("updated_at_ms"),
            }
            for item in source.get("approvals") or []
        ],
        "response_tasks": [
            {
                "task_id": item.get("task_id"),
                "status": item.get("status"),
                "updated_at_ms": item.get("updated_at_ms"),
            }
            for item in source.get("response_tasks") or []
        ],
        "response_attempts": [
            {
                "attempt_id": item.get("attempt_id"),
                "outcome": item.get("outcome"),
                "created_at_ms": item.get("created_at_ms"),
            }
            for item in source.get("response_attempts") or []
        ],
        "audit_events": [
            {
                "audit_id": item.get("audit_id"),
                "action": item.get("action"),
                "created_at_ms": item.get("created_at_ms"),
            }
            for item in source.get("audit_events") or []
        ],
    }
    return _canonical_hash(material)


def _source_as_of_ms(source: dict[str, Any]) -> int:
    values = [int(source["case"].get("updated_at_ms") or 0)]
    for collection in (
        "events",
        "agent_runs",
        "validations",
        "approvals",
        "approval_votes",
        "response_tasks",
        "response_attempts",
        "audit_events",
    ):
        for item in source.get(collection) or []:
            values.extend(
                int(item.get(field) or 0)
                for field in ("created_at_ms", "updated_at_ms")
            )
    return max(values or [0])


class CaseResponseService:
    """Create evidence-cited response drafts without executing or sending them."""

    def __init__(self, repo, policy):  # noqa: ANN001
        self.repo = repo
        self.policy = policy

    def timeline(
        self, case_id: str, *, limit: int = 20, offset: int = 0
    ) -> dict[str, Any]:
        page_limit = max(1, min(int(limit), 100))
        page_offset = max(0, int(offset))
        page = self.repo.get_case_timeline_page(
            case_id, limit=page_limit, offset=page_offset
        )
        if not page:
            raise KeyError("case not found")
        total = int(page["total"])
        case = page["case"]
        timeline_revision = _canonical_hash(
            {
                "case_id": case["case_id"],
                "case_updated_at_ms": case["updated_at_ms"],
                "total": total,
                "latest_recorded_at_ms": page["latest_recorded_at_ms"],
            }
        )
        return {
            "case": {
                key: case.get(key)
                for key in (
                    "case_id",
                    "product",
                    "status",
                    "severity",
                    "classification",
                    "summary",
                )
            },
            "timeline_revision": timeline_revision,
            "items": [_timeline_page_item(item) for item in page["items"]],
            "pagination": {
                "total": total,
                "limit": page_limit,
                "offset": page_offset,
                "page": page_offset // page_limit + 1,
                "total_pages": max(1, (total + page_limit - 1) // page_limit),
            },
        }

    def latest(self, case_id: str) -> dict[str, Any] | None:
        source = self.repo.get_case_response_source(case_id)
        if not source:
            raise KeyError("case not found")
        artifact = self.repo.get_latest_case_response_artifact(case_id)
        if not artifact:
            return None
        current_hash = source_snapshot_hash(source)
        artifact["freshness"] = {
            "is_stale": artifact["source_snapshot_hash"] != current_hash,
            "current_snapshot_hash": current_hash,
        }
        return artifact

    def generate(self, case_id: str, *, actor: str) -> dict[str, Any]:
        source = self.repo.get_case_response_source(case_id)
        if not source:
            raise KeyError("case not found")
        snapshot_hash = source_snapshot_hash(source)
        timeline = build_case_timeline(source)
        content, refs, validation, model_metadata = self._build_pack(
            source, timeline, snapshot_hash
        )
        content = self.policy.redact(content)
        content_hash = _canonical_hash(content)
        digest = hashlib.sha256(
            f"{case_id}\0{snapshot_hash}\0{content_hash}".encode("utf-8")
        ).hexdigest()[:20]
        created_at_ms = now_ms()
        artifact = {
            "artifact_id": f"response_pack_{digest}",
            "case_id": case_id,
            "schema_version": PACK_SCHEMA_VERSION,
            "source_snapshot_hash": snapshot_hash,
            "content_hash": content_hash,
            "content": content,
            "validation_status": validation["status"],
            "validation": validation,
            "generator": PACK_GENERATOR,
            "model_metadata": model_metadata,
            "created_by": str(actor or "soc-analyst")[:200],
            "created_at_ms": created_at_ms,
        }
        with self.repo.transaction():
            saved, created = self.repo.insert_case_response_artifact(
                artifact, refs, _commit=False
            )
            self.repo.insert_audit(
                new_id("audit"),
                case_id,
                str(actor or "soc-analyst"),
                "case_response_pack_generated" if created else "case_response_pack_reused",
                {
                    "case_id": case_id,
                    "artifact_id": saved["artifact_id"],
                    "version": saved["version"],
                    "source_snapshot_hash": snapshot_hash,
                    "validation_status": saved["validation_status"],
                },
                _commit=False,
            )
        saved["freshness"] = {
            "is_stale": False,
            "current_snapshot_hash": snapshot_hash,
        }
        return {"artifact": saved, "created": created}

    def _build_pack(
        self,
        source: dict[str, Any],
        timeline: list[dict[str, Any]],
        snapshot_hash: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
        case = source["case"]
        latest_run = (source.get("agent_runs") or [{}])[0]
        latest_result = (
            latest_run.get("result")
            if isinstance(latest_run.get("result"), dict)
            else {}
        )
        latest_validation = (source.get("validations") or [{}])[0]
        events_by_id = {
            str(item.get("event_id") or ""): item
            for item in source.get("events") or []
        }
        latest_event = events_by_id.get(str(latest_run.get("event_id") or ""))
        if not latest_event:
            non_replay = [
                item for item in source.get("events") or [] if not _event_is_replay(item)
            ]
            latest_event = (non_replay or source.get("events") or [{}])[-1]
        latest_refs = _event_refs(latest_event)

        security_entries = [
            item for item in timeline if item.get("kind") == "security_event"
        ]
        key_facts = [
            {
                "claim_id": f"fact-{index + 1}",
                "text": item["title"],
                "occurred_at_ms": item["occurred_at_ms"],
                "time_basis": item["time_basis"],
                "evidence_refs": item["evidence_refs"],
            }
            for index, item in enumerate(security_entries[-5:])
        ]
        explanation = (
            latest_result.get("explanation")
            if isinstance(latest_result.get("explanation"), dict)
            else {}
        )
        pending_approvals = [
            str(item.get("approval_id") or "")
            for item in source.get("approvals") or []
            if item.get("status") == "pending"
        ]
        case_summary = {
            "headline": _bounded_text(
                case.get("summary") or latest_result.get("summary") or case["case_id"],
                500,
            ),
            "headline_evidence_refs": latest_refs,
            "current_assessment": _bounded_text(
                explanation.get("verdict")
                or latest_result.get("summary")
                or case.get("classification"),
                1_500,
            ),
            "classification": case.get("classification"),
            "confidence": case.get("confidence"),
            "severity": case.get("severity"),
            "key_facts": key_facts,
            "uncertainties": [
                _bounded_text(item, 500)
                for item in latest_result.get("missing_evidence") or []
                if _bounded_text(item, 500)
            ][:12],
            "pending_decisions": pending_approvals,
            "as_of_ms": _source_as_of_ms(source),
        }

        validation_passed = latest_validation.get("status") == "passed"
        routing_eligible = bool(
            validation_passed
            and case.get("status") not in _TERMINAL_CASE_STATUSES
            and latest_event
        )
        containment_options = []
        fine_grained_candidate: dict[str, Any] | None = None
        if case.get("classification") in {"malicious", "suspicious"} and latest_event:
            normalized = NormalizedEvent(
                event_id=str(latest_event.get("event_id") or ""),
                source=str(latest_event.get("source") or ""),
                product=str(latest_event.get("product") or ""),
                event_type=str(latest_event.get("event_type") or ""),
                severity=str(latest_event.get("severity") or ""),
                timestamp=str(latest_event.get("timestamp") or ""),
                entities=dict(latest_event.get("entities") or {}),
                evidence=list(latest_event.get("evidence") or []),
                sensitivity_tags=list(latest_event.get("sensitivity_tags") or []),
                raw_ref=str(latest_event.get("alert_id") or ""),
            )
            default_ttl = int(self.repo.get_response_policy()["default_ttl_seconds"])
            compiled = compile_response_action(
                "临时封禁恶意来源 IP", normalized, default_ttl_seconds=default_ttl
            )
            if compiled:
                context = dict(compiled.get("scope") or {})
                event_entities = (
                    latest_event.get("entities")
                    if isinstance(latest_event.get("entities"), dict)
                    else {}
                )
                if not context.get("host"):
                    context["host"] = str(
                        event_entities.get("host")
                        or event_entities.get("dst_ip")
                        or ""
                    )[:512]
                containment_options.append(
                    {
                        "step_id": "contain-source-ip",
                        "action_type": ACTION_BLOCK_IP,
                        "object": compiled["object"],
                        "scope": {
                            "enforced": {
                                "source_ip": compiled["source_ip"],
                                "cidr": compiled["object"],
                            },
                            "context_only": context,
                        },
                        "duration_seconds": compiled["duration_seconds"],
                        "source_event_id": compiled["event_id"],
                        "evidence_hash": compiled["evidence_hash"],
                        "evidence_refs": latest_refs,
                        "mode": "approve_required",
                        "state": "draft_only",
                        "routing_eligible": routing_eligible,
                        "required_connector_capability": "network.source_ip",
                        "scope_guarantee": "source_ip_and_ttl_only",
                        "boundary_note": "现有连接器只保证来源 IP 与 TTL；产品、Host 和 Path 仅作为上下文，不构成执行约束。",
                        "rollback": "移除临时来源 IP 规则，并核验访问恢复情况。",
                    }
                )
                if (
                    context.get("product") == "waf"
                    and context.get("host")
                    and context.get("path")
                ):
                    fine_grained_candidate = {
                        "candidate_id": "waf-host-path-source-ip",
                        "state": "blocked",
                        "mode": "draft_only",
                        "routing_eligible": False,
                        "required_connector_capability": "waf.host_path.source_ip",
                        "scope": {
                            "source_ip": compiled["source_ip"],
                            "host": context["host"],
                            "path": context["path"],
                        },
                        "duration_seconds": compiled["duration_seconds"],
                        "evidence_refs": latest_refs,
                        "blocked_reason": "当前连接器没有能力声明与运行时校验，无法保证 Host + Path + 来源 IP 的组合约束，因此不得进入审批或执行链。",
                    }

        playbook = [
            {
                "step_id": "verify-evidence",
                "stage": "verify",
                "mode": "read_only",
                "action": "复核标准化证据与尚未闭合的证据缺口。",
                "rationale": "响应决策必须能够追溯到当前 Case 的受治理证据。",
                "evidence_refs": latest_refs,
                "success_criteria": "分析员逐项记录引用事实是已确认还是仍待确认。",
                "rollback": "",
            }
        ]
        seen_actions = {"复核标准化证据与尚未闭合的证据缺口。"}
        for index, item in enumerate(latest_result.get("recommended_actions") or []):
            if not isinstance(item, dict):
                continue
            action = _bounded_text(item.get("action"), 800)
            key = action.casefold()
            if not action or key in seen_actions:
                continue
            seen_actions.add(key)
            stage = str(item.get("stage") or action_stage(action))
            if stage not in ACTION_STAGE_ORDER:
                stage = action_stage(action)
            mode = str(item.get("mode") or self.policy.action_mode(action))
            if mode not in {"observe", "automated_read_only", "approve_required"}:
                mode = "approve_required" if self.policy.requires_approval(action) else "observe"
            playbook.append(
                {
                    "step_id": f"{stage}-{index + 1}",
                    "stage": stage,
                    "mode": mode,
                    "action": _bounded_text(self.policy.safe_action_text(action), 1_000),
                    "rationale": _bounded_text(item.get("rationale"), 1_000),
                    "evidence_refs": latest_refs,
                    "success_criteria": "由获授权的分析员记录执行结果与支撑证据。",
                    "rollback": _bounded_text(item.get("rollback"), 1_000),
                }
            )
            if len(playbook) >= MAX_PLAYBOOK_STEPS:
                break
        playbook.sort(
            key=lambda item: (
                ACTION_STAGE_ORDER.get(str(item.get("stage") or ""), 99),
                str(item.get("step_id") or ""),
            )
        )

        actions_taken = []
        actions_pending = []
        simulations = []
        exceptions = []
        for task in source.get("response_tasks") or []:
            action = task.get("action") if isinstance(task.get("action"), dict) else {}
            label = _bounded_text(
                f"{task.get('action_type')}: {action.get('object') or 'governed target'}",
                500,
            )
            item = {
                "text": label,
                "task_id": task.get("task_id"),
                "state": task.get("status"),
                "evidence_refs": _source_event_refs(
                    events_by_id, task.get("event_id")
                ),
            }
            status = str(task.get("status") or "")
            if status == "verified":
                actions_taken.append(item)
            elif status == "rolled_back":
                item["text"] = f"已回滚：{label}"
                actions_taken.append(item)
            elif status == "shadowed":
                simulations.append(item)
            elif status in {
                "waiting_configuration",
                "waiting_dispatch",
                "paused",
                "queued",
                "running",
                "retry_wait",
                "rollback_queued",
                "rollback_running",
                "rollback_retry",
            }:
                actions_pending.append(item)
            elif status in {"failed", "rollback_failed"}:
                exceptions.append(item)

        communication = {
            "audience": "internal_soc_and_business_owner",
            "status": "draft_only",
            "delivery_state": "not_sent",
            "subject": _bounded_text(
                f"[内部事件通报草稿] {str(case.get('severity') or '').upper()} Case {case['case_id']}",
                300,
            ),
            "situation": case_summary["headline"],
            "known_facts": key_facts,
            "business_impact": _bounded_text(
                explanation.get("business_impact")
                or "业务影响仍在评估中，当前证据不足以确认影响范围。",
                1_500,
            ),
            "actions_taken": actions_taken,
            "actions_pending": actions_pending,
            "simulations_not_production_actions": simulations,
            "execution_exceptions": exceptions,
            "unknowns": case_summary["uncertainties"],
            "next_update_trigger": "出现新证据、审批结果或已核验的响应状态后更新。",
        }

        pack = {
            "schema_version": PACK_SCHEMA_VERSION,
            "case_id": case["case_id"],
            "source_snapshot_hash": snapshot_hash,
            "case_summary": case_summary,
            "timeline_preview": timeline[-MAX_PACK_TIMELINE_ITEMS:],
            "containment": {
                "state": "draft_only",
                "allowed_action_types": [ACTION_BLOCK_IP],
                "options": containment_options,
                "fine_grained_candidate": fine_grained_candidate,
            },
            "playbook": {
                "state": "draft_only",
                "steps": playbook,
            },
            "incident_communication": communication,
            "execution_boundary": {
                "direct_execution": False,
                "direct_communication_delivery": False,
                "approval_pipeline_required": True,
            },
        }
        refs = self._artifact_refs(source, pack)
        validation = self._validate_pack(source, pack, refs)
        model_metadata = dict(explanation.get("model_runtime") or {})
        model_metadata.update(
            {
                "response_pack_generator": PACK_GENERATOR,
                "source_agent_run_id": str(latest_run.get("run_id") or ""),
                "source_prompt_version": str(latest_run.get("prompt_version") or ""),
            }
        )
        return pack, refs, validation, model_metadata

    @staticmethod
    def _artifact_refs(
        source: dict[str, Any], pack: dict[str, Any]
    ) -> list[dict[str, Any]]:
        used: set[str] = set()

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "evidence_refs" and isinstance(item, list):
                        used.update(str(ref) for ref in item if str(ref).strip())
                    else:
                        collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(pack)
        refs = []
        for event in source.get("events") or []:
            event_refs = set(_event_refs(event))
            for ref in sorted(used & event_refs):
                refs.append(
                    {
                        "claim_scope": "response_pack",
                        "ref_type": "evidence",
                        "ref_id": ref,
                        "source_event_id": str(event.get("event_id") or ""),
                        "source_hash": str(event.get("evidence_hash") or ""),
                    }
                )
        return refs

    @staticmethod
    def _validate_pack(
        source: dict[str, Any],
        pack: dict[str, Any],
        refs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        allowed_refs = {
            ref
            for event in source.get("events") or []
            for ref in _event_refs(event)
        }
        cited_refs: set[str] = set()

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "evidence_refs" and isinstance(item, list):
                        cited_refs.update(str(ref) for ref in item if str(ref).strip())
                    else:
                        collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(pack)
        containment_types = {
            str(item.get("action_type") or "")
            for item in pack["containment"]["options"]
            if isinstance(item, dict)
        }
        checks = {
            "evidence_available": bool(allowed_refs),
            "citations_resolve": bool(cited_refs) and cited_refs.issubset(allowed_refs),
            "citation_manifest_complete": cited_refs
            == {str(item.get("ref_id") or "") for item in refs},
            "timeline_server_timestamped": all(
                item.get("time_basis") in {"reported", "ingest_fallback", "system"}
                for item in pack["timeline_preview"]
            ),
            "containment_allowlisted": containment_types.issubset({ACTION_BLOCK_IP}),
            "containment_scope_bounded": all(
                item.get("required_connector_capability") == "network.source_ip"
                and item.get("scope_guarantee") == "source_ip_and_ttl_only"
                for item in pack["containment"]["options"]
            ),
            "fine_grained_candidate_blocked": not pack["containment"].get(
                "fine_grained_candidate"
            )
            or (
                pack["containment"]["fine_grained_candidate"].get("state")
                == "blocked"
                and pack["containment"]["fine_grained_candidate"].get(
                    "routing_eligible"
                )
                is False
            ),
            "direct_execution_blocked": pack["execution_boundary"]["direct_execution"]
            is False,
            "direct_communication_blocked": pack["execution_boundary"][
                "direct_communication_delivery"
            ]
            is False,
            "communication_internal_draft": pack["incident_communication"]["audience"]
            == "internal_soc_and_business_owner"
            and pack["incident_communication"]["delivery_state"] == "not_sent",
        }
        latest_validation = (source.get("validations") or [{}])[0]
        if not checks["evidence_available"] or not checks["citations_resolve"]:
            status = "blocked"
        elif latest_validation.get("status") == "blocked":
            status = "blocked"
        elif latest_validation.get("status") != "passed":
            status = "review"
        elif not all(checks.values()):
            status = "blocked"
        else:
            status = "passed"
        return {
            "status": status,
            "validator": "case-response-pack-validator",
            "validator_version": "1.0.0",
            "checks": checks,
            "findings": [key for key, value in checks.items() if not value],
        }
