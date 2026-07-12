from __future__ import annotations

import threading
from contextlib import contextmanager

from .agents.base import run_id
from .agents.registry import build_agent
from .database import Repository
from .llm import LLMClient, LocalHeuristicLLM
from .memory import MemoryManager
from .models import AgentResult, NormalizedEvent, RawAlert, RecommendedAction, new_id
from .normalizer import EventNormalizer
from .policy import PolicyEngine
from .response import ResponseAdvisor
from .skills import SkillRegistry
from .validation import Validator


class Orchestrator:
    def __init__(
        self,
        repo: Repository,
        normalizer: EventNormalizer,
        memory: MemoryManager,
        llm: LLMClient,
        policy: PolicyEngine,
        skills: SkillRegistry | None = None,
        validator: Validator | None = None,
        response_advisor: ResponseAdvisor | None = None,
    ):
        self.repo = repo
        self.normalizer = normalizer
        self.memory = memory
        self.llm = llm
        self.policy = policy
        self.skills = skills or SkillRegistry()
        self.validator = validator or Validator(policy)
        self.response_advisor = response_advisor or ResponseAdvisor(policy)
        # Keep only active locks: duplicate deliveries of the same alert wait for
        # the original analysis, while unrelated alerts retain full concurrency.
        self._alert_locks: dict[str, tuple[threading.Lock, int]] = {}
        self._alert_locks_guard = threading.Lock()

    def handle_alert(self, alert: RawAlert) -> AgentResult:
        with self._lock_for_alert(alert.alert_id):
            return self._handle_alert_locked(alert)

    @contextmanager
    def _lock_for_alert(self, alert_id: str):
        with self._alert_locks_guard:
            lock, users = self._alert_locks.get(alert_id, (threading.Lock(), 0))
            self._alert_locks[alert_id] = (lock, users + 1)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
            with self._alert_locks_guard:
                current_lock, users = self._alert_locks.get(alert_id, (lock, 1))
                if users <= 1:
                    self._alert_locks.pop(alert_id, None)
                else:
                    self._alert_locks[alert_id] = (current_lock, users - 1)

    def _handle_alert_locked(self, alert: RawAlert) -> AgentResult:
        trace_id = new_id("trace")
        # Ingest (raw alert + normalized event + received audit) is one atomic
        # transaction. The LLM call is deliberately kept OUT of any transaction so
        # a slow model does not hold the repo lock and serialize all alerts.
        event = self.normalizer.normalize(alert)
        with self.repo.transaction():
            self.repo.insert_audit(
                new_id("audit"), trace_id, "gateway", "alert_received",
                {"alert_id": alert.alert_id, "product": alert.product}, _commit=False,
            )
            self.repo.insert_raw_alert(alert, _commit=False)
            event_inserted = self.repo.insert_normalized_event(event, _commit=False)
        if not event_inserted:
            # A retry must use the persisted event, not freshly-normalized data:
            # evidence is append-only and may have been normalized under an older
            # redaction policy. If its earlier analysis completed, return that
            # exact result without an extra LLM call or memory proposal.
            event = self.repo.get_normalized_event(event.event_id) or event
            existing = self.repo.get_agent_result_for_event(event.event_id)
            if existing:
                return self._agent_result_from_dict(existing)
        case_id = self._case_id(event)
        agent = build_agent(event.product, self.llm, self.policy)
        asset_id = self.memory.asset_id_for(event)
        memory_context = self.memory.load_context(event.product, case_id=case_id, asset_id=asset_id)
        try:
            result = agent.analyze(case_id, event, memory_context)
        except Exception as exc:
            # Never abort alert handling on an LLM/network failure: audit it and
            # degrade to the deterministic heuristic so the alert still produces a
            # traceable, explainable result (risk 6: model dependency).
            self.repo.insert_audit(
                new_id("audit"), trace_id, agent.name, "analysis_failed",
                {"error": str(exc), "fallback": "local_heuristic"},
            )
            try:
                fallback_agent = build_agent(event.product, LocalHeuristicLLM(), self.policy)
                result = fallback_agent.analyze(case_id, event, memory_context)
                result.summary = f"[LLM 降级为本地启发式] {result.summary}"
            except Exception as exc2:
                # Heuristic itself failed: record and re-raise. The ingest
                # transaction above is already committed, so the raw alert is
                # preserved for replay even though no case was produced.
                self.repo.insert_audit(
                    new_id("audit"), trace_id, agent.name, "analysis_failed",
                    {"error": str(exc2), "fallback": "local_heuristic_failed"},
                )
                raise
        analysis_skill = self.skills.for_product(event.product)
        validation = self.validator.validate(case_id, event, result, analysis_skill)
        approvals = self.response_advisor.prepare(event.event_id, result, validation)
        result.explanation["skill"] = {
            "name": analysis_skill.name,
            "version": analysis_skill.version,
            "risk_level": analysis_skill.risk_level,
        }
        result.explanation["validation"] = validation.to_dict()
        result.explanation["approval_request_ids"] = [item.approval_id for item in approvals]
        result.dashboard_cards.append({"title": "验证门禁", "body": validation.status})
        if validation.status == "blocked":
            result.missing_evidence.append("Validator 已阻断审批流转，请按验证发现补证或修正策略违规。")

        # Post-analysis writes are atomic: case row, link, agent run, validation,
        # approval requests, case memory and audit all commit together.
        # A mid-sequence failure cannot leave a case with an agent_run but no
        # validation, approval, memory or completion audit (or vice-versa).
        # record_case_summary opens a nested transaction (no-op commit) and its
        # inner writes use _commit=False, deferring to this outer commit.
        with self.repo.transaction():
            # Case row must exist before case_alert_links (FK case_id → cases) and
            # before agent_runs (FK case_id → cases). Linking after analysis is
            # safe: analysis and memory loading do not depend on the link row.
            self.repo.upsert_case(result, event.product, _commit=False)
            self.repo.link_case_alert(case_id, alert.alert_id, event.event_id, _commit=False)
            analysis_run_id = run_id()
            self.repo.insert_agent_run(
                analysis_run_id, result, event.product, agent.prompt_version, event.event_id, _commit=False
            )
            self.repo.insert_validation(validation.to_dict(), _commit=False)
            for approval in approvals:
                self.repo.insert_approval(approval.to_dict(), _commit=False)
            self.memory.record_case_summary(event.product, result, asset_id=asset_id, trace_id=trace_id)
            self.repo.insert_audit(
                new_id("audit"), trace_id, agent.name, "analysis_completed", result.to_dict(), _commit=False,
            )
            self.repo.insert_audit(
                new_id("audit"), trace_id, self.validator.name, "validation_completed",
                {
                    "case_id": case_id,
                    "event_id": event.event_id,
                    "analysis_run_id": analysis_run_id,
                    "status": validation.status,
                    "findings": [finding.code for finding in validation.findings],
                },
                _commit=False,
            )
            for approval in approvals:
                self.repo.insert_audit(
                    new_id("audit"), trace_id, self.response_advisor.name, "approval_requested",
                    {
                        "approval_id": approval.approval_id,
                        "case_id": case_id,
                        "event_id": event.event_id,
                        "action": approval.action,
                        "execution_status": "not_executed",
                    },
                    _commit=False,
                )
        return result

    @staticmethod
    def _agent_result_from_dict(payload: dict) -> AgentResult:
        """Rehydrate a persisted result for an idempotent alert retry."""
        actions = [
            item if isinstance(item, RecommendedAction) else RecommendedAction(**item)
            for item in payload.get("recommended_actions", [])
            if isinstance(item, (RecommendedAction, dict))
        ]
        return AgentResult(
            case_id=str(payload["case_id"]),
            agent=str(payload["agent"]),
            classification=str(payload["classification"]),
            confidence=float(payload["confidence"]),
            severity=str(payload["severity"]),
            summary=str(payload["summary"]),
            evidence=list(payload.get("evidence", [])),
            missing_evidence=list(payload.get("missing_evidence", [])),
            recommended_actions=actions,
            dashboard_cards=list(payload.get("dashboard_cards", [])),
            explanation=dict(payload.get("explanation", {})),
            created_at_ms=int(payload.get("created_at_ms", 0)),
        )

    def _case_id(self, event: NormalizedEvent) -> str:
        host = event.entities.get("host") or event.entities.get("src_ip") or "unknown"
        rule = event.entities.get("rule") or event.event_type
        return f"case_{event.product}_{str(host).replace('.', '_')}_{str(rule).replace(' ', '_')}"[:96]
