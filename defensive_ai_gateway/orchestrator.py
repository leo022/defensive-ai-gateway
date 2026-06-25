from __future__ import annotations

from .agents.base import run_id
from .agents.registry import build_agent
from .database import Repository
from .llm import LLMClient
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
        self.repo.insert_audit(new_id("audit"), trace_id, "gateway", "alert_received", {"alert_id": alert.alert_id, "product": alert.product})
        self.repo.insert_raw_alert(alert)
        event = self.normalizer.normalize(alert)
        self.repo.insert_normalized_event(event)
        case_id = self._case_id(event)
        self.repo.link_case_alert(case_id, alert.alert_id, event.event_id)
        agent = build_agent(event.product, self.llm, self.policy)
        asset_id = self.memory.asset_id_for(event)
        memory_context = self.memory.load_context(event.product, case_id=case_id, asset_id=asset_id)
        result = agent.analyze(case_id, event, memory_context)
        self.repo.upsert_case(result, event.product)
        self.repo.insert_agent_run(run_id(), result, event.product, agent.prompt_version)
        self.memory.record_case_summary(event.product, result, asset_id=asset_id, trace_id=trace_id)
        self.repo.insert_audit(new_id("audit"), trace_id, agent.name, "analysis_completed", result.to_dict())
        return result

    def _case_id(self, event: NormalizedEvent) -> str:
        host = event.entities.get("host") or event.entities.get("src_ip") or "unknown"
        rule = event.entities.get("rule") or event.event_type
        return f"case_{event.product}_{str(host).replace('.', '_')}_{str(rule).replace(' ', '_')}"[:96]
