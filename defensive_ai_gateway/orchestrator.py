from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager

from .agents.base import run_id
from .agents.registry import build_agent
from .database import Repository
from .llm import LLMClient, LLMEndpointConfigurationError, LocalHeuristicLLM
from .memory import MemoryManager
from .memory_matcher import MemoryMatchEvaluation, MemoryMatcher
from .models import AgentResult, NormalizedEvent, RawAlert, RecommendedAction, new_id
from .normalizer import EventNormalizer
from .policy import PolicyEngine
from .processing import AlertRetryableError
from .response import ResponseAdvisor
from .skills import SkillRegistry
from .validation import Validator


class Orchestrator:
    CASE_CORRELATION_WINDOW_MS = 60 * 60 * 1000
    CROSS_PRODUCT_WINDOW_MS = 15 * 60 * 1000
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
        memory_matcher: MemoryMatcher | None = None,
    ):
        self.repo = repo
        self.normalizer = normalizer
        self.memory = memory
        self.llm = llm
        self.policy = policy
        self.skills = skills or SkillRegistry()
        self.validator = validator or Validator(policy)
        self.response_advisor = response_advisor or ResponseAdvisor(policy)
        self.memory_matcher = memory_matcher or MemoryMatcher()
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
        return self._analyze_event(alert=alert, event=event, trace_id=trace_id)

    def reanalyze_existing_alert(
        self,
        *,
        alert: RawAlert,
        source_event_id: str,
        case_id: str,
        correlation_key: str = "",
        actor: str = "runtime-operator",
        replay_context: dict | None = None,
    ) -> tuple[AgentResult, bool]:
        """Append a corrected analysis version for one immutable raw alert.

        Delivery retries reuse the original normalized event by design. A human
        requested re-analysis is different: it normalizes retained raw evidence
        under the current profile, writes a distinct deterministic event version,
        and refreshes the live Case summary without deleting prior runs.
        """
        if not source_event_id or not case_id:
            raise ValueError("source_event_id and case_id are required for analysis replay")
        if not str(alert.alert_id or "").strip():
            raise ValueError("analysis replay requires a stable source alert id")

        lock_id = f"{alert.alert_id}:analysis-replay"
        with self._lock_for_alert(lock_id):
            current_case = self.repo.get_case(case_id)
            if not current_case:
                raise KeyError("case not found")
            if str(current_case.get("product") or "").lower() != alert.product.lower():
                raise ValueError("alert product does not match the Case")

            event = self.normalizer.normalize(alert)
            agent = build_agent(event.product, self.llm, self.policy)
            replay_material = {
                "source_event_id": source_event_id,
                "prompt_version": agent.prompt_version,
                "entities": event.entities,
                "evidence": event.evidence,
            }
            replay_fingerprint = hashlib.sha256(
                json.dumps(replay_material, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()[:16]
            event.event_id = f"{source_event_id}__replay_{replay_fingerprint}"
            metadata = {
                "case_id": case_id,
                "source_alert_id": alert.alert_id,
                "source_event_id": source_event_id,
                "replay_event_id": event.event_id,
                "prompt_version": agent.prompt_version,
                **dict(replay_context or {}),
            }
            event.evidence.append(
                {
                    "ref": source_event_id,
                    "source": "gateway",
                    "type": "analysis_replay",
                    "value": {
                        "source_event_id": source_event_id,
                        "prompt_version": agent.prompt_version,
                    },
                    "why_it_matters": "该事件由授权分析师基于保留的原始告警重新映射并复核。",
                }
            )

            existing = self.repo.get_agent_result_for_event(event.event_id)
            if existing:
                self.repo.insert_audit(
                    new_id("audit"),
                    event.event_id,
                    str(actor or "runtime-operator"),
                    "analysis_replay_reused",
                    metadata,
                )
                return self._agent_result_from_dict(existing), False

            trace_id = new_id("trace")
            with self.repo.transaction():
                inserted = self.repo.insert_normalized_event(event, _commit=False)
                self.repo.insert_audit(
                    new_id("audit"),
                    trace_id,
                    str(actor or "runtime-operator"),
                    "analysis_replay_requested",
                    metadata,
                    _commit=False,
                )
            if not inserted:
                event = self.repo.get_normalized_event(event.event_id) or event
                existing = self.repo.get_agent_result_for_event(event.event_id)
                if existing:
                    return self._agent_result_from_dict(existing), False

            return (
                self._analyze_event(
                    alert=alert,
                    event=event,
                    trace_id=trace_id,
                    target_case_id=case_id,
                    correlation_key=str(current_case.get("correlation_key") or correlation_key),
                    case_resolution="analysis_replay",
                    record_memory=False,
                    replay_metadata=metadata,
                ),
                True,
            )

    def _analyze_event(
        self,
        *,
        alert: RawAlert,
        event: NormalizedEvent,
        trace_id: str,
        target_case_id: str | None = None,
        correlation_key: str = "",
        case_resolution: str = "",
        record_memory: bool = True,
        replay_metadata: dict | None = None,
    ) -> AgentResult:
        if target_case_id:
            case_id = target_case_id
            correlation_key = correlation_key or self._case_correlation_key(event)
            case_resolution = case_resolution or "analysis_replay"
        else:
            correlation_key = self._case_correlation_key(event)
            case_id, case_resolution = self.repo.resolve_case_id(
                correlation_key,
                event.event_id,
                event.timestamp,
                window_ms=self.CASE_CORRELATION_WINDOW_MS,
            )
        # alert_received is deliberately persisted before model work, when the
        # Case is not known yet. Record the explicit relationship as soon as
        # correlation resolves it so audit retention never relies on trace_id
        # accidentally being equal to case_id.
        self.repo.link_audit_trace_to_case(trace_id, case_id)
        agent = build_agent(event.product, self.llm, self.policy)
        asset_id = self.memory.asset_id_for(event)
        # Keep governance status current even when operators do not manually run
        # a sweep. Expired memories are therefore never presented as live context.
        self.memory.expire_due()
        memory_context = self.memory.load_context(event.product, case_id=case_id, asset_id=asset_id)
        if replay_metadata:
            # A replaced conclusion must not feed itself back into its corrected
            # run through low-trust case memory or pending candidates.
            memory_context["case_short_term"] = []
            memory_context["evidence_refs"] = []
            memory_context["product_long_term"] = [
                item
                for item in memory_context.get("product_long_term", [])
                if str(item.get("source_case_id") or "") != case_id
            ]
        cross_product_context = self.repo.query_correlated_alerts(
            event,
            window_ms=self.CROSS_PRODUCT_WINDOW_MS,
            limit=20,
        )
        memory_context["cross_product_context"] = cross_product_context
        match_candidates = self.memory.load_match_candidates(
            event.product,
            limit=self.memory_matcher.config.candidate_limit,
        )
        if replay_metadata:
            match_candidates = [
                item
                for item in match_candidates
                if str(item.get("source_case_id") or "") != case_id
            ]
        memory_evaluation = self.memory_matcher.match(event, match_candidates)
        memory_context["product_long_term"] = [
            candidate.memory
            for candidate in memory_evaluation.candidates
            if candidate.overall_score >= memory_evaluation.review_threshold
        ][: self.memory_matcher.config.top_k]
        memory_context["memory_association"] = memory_evaluation.context_payload(
            self.memory_matcher.config.top_k
        )
        model_runtime = dict(self.llm.runtime_metadata)
        fallback_used = False
        try:
            result = agent.analyze(case_id, event, memory_context)
        except Exception as exc:
            if isinstance(exc, LLMEndpointConfigurationError):
                # A WebSocket-only endpoint cannot recover on its own. Preserve
                # the alert as a terminal failure instead of requeueing it forever.
                self.repo.insert_audit(
                    new_id("audit"), trace_id, agent.name, "analysis_failed",
                    {
                        "provider": model_runtime.get("provider", "unknown"),
                        "endpoint_host": model_runtime.get("endpoint_host", ""),
                        "error_type": type(exc).__name__,
                        "reason": str(exc),
                        "fallback": "not_used",
                    },
                )
                raise
            if self.llm.defer_on_failure:
                retry_after = self.llm.retry_after_seconds
                # Remote-model output must not silently become a local judgment.
                # The raw alert and normalized event are already durable above;
                # returning this typed error lets the inbox retry it after the
                # circuit-breaker window instead of treating it as completed.
                self.repo.insert_audit(
                    new_id("audit"), trace_id, agent.name, "analysis_deferred",
                    {
                        "provider": model_runtime.get("provider", "unknown"),
                        "endpoint_host": model_runtime.get("endpoint_host", ""),
                        "error_type": type(exc).__name__,
                        "retry_after_seconds": retry_after,
                    },
                )
                raise AlertRetryableError(
                    "remote LLM analysis deferred for durable retry",
                    retry_after_seconds=retry_after,
                ) from exc

            # Custom/test analyzers retain the historical deterministic fallback
            # unless they explicitly declare remote retry semantics above.
            self.repo.insert_audit(
                new_id("audit"), trace_id, agent.name, "analysis_failed",
                {"error": str(exc), "fallback": "local_heuristic"},
            )
            try:
                fallback_used = True
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
        result = self.memory_matcher.reconcile(result, memory_evaluation)
        result.explanation["model_runtime"] = {
            **model_runtime,
            "fallback_used": fallback_used,
            "effective_provider": "local" if fallback_used else model_runtime.get("provider", "unknown"),
        }
        result.explanation["cross_product_correlation"] = {
            "window_ms": self.CROSS_PRODUCT_WINDOW_MS,
            "match_count": len(cross_product_context),
            "event_ids": [item["event_id"] for item in cross_product_context],
        }
        result.dashboard_cards.append(
            {"title": "跨产品关联", "body": str(len(cross_product_context))}
        )
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
        if replay_metadata:
            result.explanation["analysis_replay"] = dict(replay_metadata)
        result.explanation["memory_write_status"] = (
            "committed"
            if validation.status == "passed" and record_memory
            else "suppressed_for_analysis_replay"
            if replay_metadata
            else "suppressed_by_validator"
        )

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
            alert_at_ms = self.repo.timestamp_ms(event.timestamp)
            self.repo.upsert_case(
                result,
                event.product,
                _commit=False,
                correlation_key=correlation_key,
                alert_at_ms=alert_at_ms,
            )
            self.repo.link_case_alert(
                case_id,
                alert.alert_id,
                event.event_id,
                _commit=False,
                alert_at_ms=alert_at_ms,
            )
            analysis_run_id = run_id()
            self.repo.insert_agent_run(
                analysis_run_id, result, event.product, agent.prompt_version, event.event_id, _commit=False
            )
            self._persist_memory_matches(memory_evaluation, case_id, analysis_run_id)
            self.repo.insert_validation(validation.to_dict(), _commit=False)
            cancelled_approvals = self.repo.cancel_pending_approvals(
                case_id,
                actor=self.response_advisor.name,
                reason=f"Superseded by analysis for event {event.event_id}",
                _commit=False,
            )
            for approval in approvals:
                self.repo.insert_approval(approval.to_dict(), _commit=False)
            if validation.status == "passed" and record_memory:
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
            self.repo.insert_audit(
                new_id("audit"), trace_id, "cross-product-correlator", "cross_product_context_loaded",
                {
                    "case_id": case_id,
                    "event_id": event.event_id,
                    "window_ms": self.CROSS_PRODUCT_WINDOW_MS,
                    "matches": [
                        {
                            "event_id": item["event_id"],
                            "product": item["product"],
                            "matched_entities": item["matched_entities"],
                            "time_delta_ms": item["time_delta_ms"],
                        }
                        for item in cross_product_context
                    ],
                },
                _commit=False,
            )
            self.repo.insert_audit(
                new_id("audit"), trace_id, "case-correlator", "case_resolution",
                {
                    "case_id": case_id,
                    "correlation_key": correlation_key,
                    "resolution": case_resolution,
                    "window_ms": self.CASE_CORRELATION_WINDOW_MS,
                },
                _commit=False,
            )
            if replay_metadata:
                self.repo.insert_audit(
                    new_id("audit"),
                    trace_id,
                    "analysis-replay",
                    "analysis_replay_completed",
                    {
                        **replay_metadata,
                        "analysis_run_id": analysis_run_id,
                        "classification": result.classification,
                        "confidence": result.confidence,
                        "validation_status": validation.status,
                    },
                    _commit=False,
                )
            if cancelled_approvals:
                self.repo.insert_audit(
                    new_id("audit"), trace_id, self.response_advisor.name, "approvals_cancelled",
                    {
                        "case_id": case_id,
                        "event_id": event.event_id,
                        "count": cancelled_approvals,
                        "reason": "superseded_by_new_analysis",
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

    def _persist_memory_matches(
        self,
        evaluation: MemoryMatchEvaluation,
        case_id: str,
        analysis_run_id: str,
    ) -> None:
        if not evaluation.candidates:
            return
        self.repo.insert_memory_matches(
            event_id=evaluation.event_id,
            alert_id=evaluation.alert_id,
            case_id=case_id,
            analysis_run_id=analysis_run_id,
            matcher_version=evaluation.matcher_version,
            final_effect=evaluation.final_effect,
            candidates=[candidate.to_dict() for candidate in evaluation.candidates],
            _commit=False,
        )

    @staticmethod
    def _agent_result_from_dict(payload: dict) -> AgentResult:
        """Rehydrate a persisted result for an idempotent alert retry."""
        return AgentResult.from_dict(payload)

    def _case_correlation_key(self, event: NormalizedEvent) -> str:
        host = event.entities.get("host") or event.entities.get("src_ip") or "unknown"
        rule = event.entities.get("rule") or event.event_type
        return f"case_{event.product}_{str(host).replace('.', '_')}_{str(rule).replace(' ', '_')}"[:96]

    def _case_id(self, event: NormalizedEvent) -> str:
        """Backwards-compatible base key helper used by older integrations."""
        return self._case_correlation_key(event)
