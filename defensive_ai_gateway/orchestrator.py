from __future__ import annotations

from .agents.base import run_id
from .agents.registry import build_agent
from .database import Repository
from .llm import LLMClient, LocalHeuristicLLM
from .memory import MemoryManager
from .models import AgentResult, NormalizedEvent, RawAlert, new_id
from .normalizer import EventNormalizer
from .policy import PolicyEngine


class Orchestrator:
    def __init__(self, repo: Repository, normalizer: EventNormalizer, memory: MemoryManager, llm: LLMClient, policy: PolicyEngine):
        self.repo = repo
        self.normalizer = normalizer
        self.memory = memory
        self.llm = llm
        self.policy = policy

    def handle_alert(self, alert: RawAlert) -> AgentResult:
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
            self.repo.insert_normalized_event(event, _commit=False)
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
        # Post-analysis writes are atomic: case row, link, agent run, case memory
        # and completion audit commit together so a mid-sequence failure cannot
        # leave a case with an agent_run but no memory/audit (or vice-versa).
        # record_case_summary opens a nested transaction (no-op commit) and its
        # inner writes use _commit=False, deferring to this outer commit.
        with self.repo.transaction():
            # Case row must exist before case_alert_links (FK case_id → cases) and
            # before agent_runs (FK case_id → cases). Linking after analysis is
            # safe: analysis and memory loading do not depend on the link row.
            self.repo.upsert_case(result, event.product, _commit=False)
            self.repo.link_case_alert(case_id, alert.alert_id, event.event_id, _commit=False)
            self.repo.insert_agent_run(run_id(), result, event.product, agent.prompt_version, _commit=False)
            self.memory.record_case_summary(event.product, result, asset_id=asset_id, trace_id=trace_id)
            self.repo.insert_audit(
                new_id("audit"), trace_id, agent.name, "analysis_completed", result.to_dict(), _commit=False,
            )
        return result

    def _case_id(self, event: NormalizedEvent) -> str:
        host = event.entities.get("host") or event.entities.get("src_ip") or "unknown"
        rule = event.entities.get("rule") or event.event_type
        return f"case_{event.product}_{str(host).replace('.', '_')}_{str(rule).replace(' ', '_')}"[:96]
