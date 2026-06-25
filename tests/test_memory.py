from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.llm import LocalHeuristicLLM
from defensive_ai_gateway.memory import (
    LAYER_CASE_SHORT_TERM,
    LAYER_EVIDENCE,
    LAYER_ORG_KNOWLEDGE,
    LAYER_PRODUCT_LONG_TERM,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_PENDING,
    STATUS_QUARANTINED,
    MemoryManager,
)
from defensive_ai_gateway.models import RawAlert, now_ms
from defensive_ai_gateway.normalizer import EventNormalizer
from defensive_ai_gateway.orchestrator import Orchestrator
from defensive_ai_gateway.policy import PolicyEngine


def _waf_alert() -> RawAlert:
    payload = json.loads(Path("samples/waf_alert.json").read_text(encoding="utf-8"))
    return RawAlert(
        source=payload["source"],
        product=payload["product"],
        event_type=payload["event_type"],
        severity=payload["severity"],
        timestamp=payload["timestamp"],
        payload=payload["payload"],
        alert_id=payload["alert_id"],
    )


def _build(tmp: Path, with_policy: bool = True):
    config = GatewayConfig()
    repo = Repository(str(tmp / "gateway.db"))
    policy = PolicyEngine(config.policy)
    memory = MemoryManager(repo, policy if with_policy else None)
    orchestrator = Orchestrator(repo, EventNormalizer(policy), memory, LocalHeuristicLLM(), policy)
    return repo, policy, memory, orchestrator


class MultiLayerMemoryTest(unittest.TestCase):
    def test_org_knowledge_seeded_on_init(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "g.db"))
            memory = MemoryManager(repo)
            org = repo.query_memory(layer=LAYER_ORG_KNOWLEDGE, limit=100)
            self.assertGreaterEqual(len(org), 5)
            self.assertTrue(all(m["status"] == STATUS_ACTIVE for m in org))
            self.assertTrue(all(m["trust_level"] == "high" for m in org))

    def test_multi_layer_context_after_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, policy, memory, orchestrator = _build(Path(tmp))
            result = orchestrator.handle_alert(_waf_alert())
            ctx = memory.load_context("waf", case_id=result.case_id, asset_id="10.30.2.44")
            # short-term case memory recorded
            self.assertGreaterEqual(len(ctx["case_short_term"]), 1)
            self.assertEqual(ctx["case_short_term"][0]["layer"], LAYER_CASE_SHORT_TERM)
            # product long-term candidate proposed (pending approval)
            self.assertGreaterEqual(len(ctx["product_long_term"]), 1)
            self.assertEqual(ctx["product_long_term"][0]["status"], STATUS_PENDING)
            # org knowledge present
            self.assertGreaterEqual(len(ctx["org_knowledge"]), 1)
            # evidence store: read-only refs, no raw secret
            self.assertGreaterEqual(len(ctx["evidence_refs"]), 1)
            ev_text = json.dumps(ctx["evidence_refs"], ensure_ascii=False)
            self.assertNotIn("demo-secret-token", ev_text)
            for ref in ctx["evidence_refs"]:
                self.assertIn("ref", ref)
                self.assertIn("summary", ref)

    def test_active_product_memory_is_loaded_before_pending_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, policy, memory, _ = _build(Path(tmp))
            repo.save_memory(
                {
                    "memory_id": "mem_active_fp",
                    "layer": LAYER_PRODUCT_LONG_TERM,
                    "namespace": memory.product_namespace("waf"),
                    "retrieval_key": "WAF-941-APP-ANOMALY",
                    "content": "false_positive: approved synthetic-browser traffic",
                    "source_case_id": "case_old",
                    "scope": "waf:false_positive_pattern",
                    "trust_level": "medium",
                    "status": STATUS_ACTIVE,
                    "sensitivity_ok": True,
                    "approved_by": "analyst-a",
                    "expires_at_ms": now_ms() + 1000000,
                }
            )
            for idx in range(8):
                repo.save_memory(
                    {
                        "memory_id": f"mem_pending_{idx}",
                        "layer": LAYER_PRODUCT_LONG_TERM,
                        "namespace": memory.product_namespace("waf"),
                        "retrieval_key": f"case_{idx}",
                        "content": f"suspicious:pending candidate {idx}",
                        "source_case_id": f"case_{idx}",
                        "scope": "",
                        "trust_level": "low",
                        "status": STATUS_PENDING,
                        "sensitivity_ok": True,
                        "approved_by": "",
                        "expires_at_ms": None,
                    }
                )
            ctx = memory.load_context("waf", limit=5)
            ids = [item["memory_id"] for item in ctx["product_long_term"]]
            self.assertIn("mem_active_fp", ids)
            self.assertEqual(ids[0], "mem_active_fp")

    def test_evidence_store_is_read_only_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, policy, memory, orchestrator = _build(Path(tmp))
            result = orchestrator.handle_alert(_waf_alert())
            refs = memory.load_evidence(result.case_id)
            self.assertGreaterEqual(len(refs), 1)
            # the evidence layer is logical/read-only: nothing is written under layer=evidence
            written = repo.query_memory(layer=LAYER_EVIDENCE, limit=100, include_expired=True)
            self.assertEqual(written, [])

    def test_promotion_requires_all_five_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, policy, memory, orchestrator = _build(Path(tmp))
            result = orchestrator.handle_alert(_waf_alert())
            pending = repo.query_memory(
                layer=LAYER_PRODUCT_LONG_TERM, namespace=memory.product_namespace("waf"), limit=10
            )
            self.assertEqual(pending[0]["status"], STATUS_PENDING)
            mem_id = pending[0]["memory_id"]

            # missing approver + scope + expiry → three gates fail (evidence + sensitivity pass)
            outcome = memory.promote(mem_id, "", "", None)
            self.assertFalse(outcome.ok)
            reason_text = " ".join(outcome.reasons)
            self.assertIn("analyst_approved", reason_text)
            self.assertIn("scope_clear", reason_text)
            self.assertIn("expiry_set", reason_text)
            self.assertNotIn("evidence_traceable", reason_text)
            self.assertNotIn("no_sensitive_leak", reason_text)

            # all five gates satisfied → promotion succeeds
            future = now_ms() + 90 * 24 * 3600 * 1000
            outcome = memory.promote(mem_id, "analyst-lee", "waf:false_positive_pattern", future, retrieval_key="WAF-941-APP-ANOMALY")
            self.assertTrue(outcome.ok, outcome.reasons)
            promoted = repo.get_memory(mem_id)
            self.assertEqual(promoted["status"], STATUS_ACTIVE)
            self.assertEqual(promoted["approved_by"], "analyst-lee")
            self.assertEqual(promoted["scope"], "waf:false_positive_pattern")
            events = repo.list_memory_events(memory_id=mem_id)
            self.assertTrue(any(e["event_type"] == "promoted" for e in events))

    def test_promotion_blocked_by_sensitive_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, policy, memory, orchestrator = _build(Path(tmp))
            result = orchestrator.handle_alert(_waf_alert())
            # craft a pending long-term candidate carrying sensitive material
            mem_id = "mem_sensitive_1"
            repo.save_memory(
                {
                    "memory_id": mem_id,
                    "layer": LAYER_PRODUCT_LONG_TERM,
                    "namespace": memory.product_namespace("waf"),
                    "retrieval_key": result.case_id,
                    "content": "Bearer demo-secret-token 应被脱敏",
                    "source_case_id": result.case_id,
                    "scope": "waf:leak_test",
                    "trust_level": "low",
                    "status": STATUS_PENDING,
                    "sensitivity_ok": True,
                    "approved_by": "",
                    "expires_at_ms": None,
                }
            )
            future = now_ms() + 90 * 24 * 3600 * 1000
            outcome = memory.promote(mem_id, "analyst-lee", "waf:leak_test", future)
            self.assertFalse(outcome.ok)
            self.assertIn("no_sensitive_leak", " ".join(outcome.reasons))

    def test_expiry_sweep(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, policy, memory, _ = _build(Path(tmp))
            repo.save_memory(
                {
                    "memory_id": "mem_expire_1",
                    "layer": LAYER_CASE_SHORT_TERM,
                    "namespace": "case/c1",
                    "retrieval_key": "c1",
                    "content": "stale",
                    "source_case_id": "c1",
                    "scope": "case:c1",
                    "trust_level": "low",
                    "status": STATUS_ACTIVE,
                    "sensitivity_ok": True,
                    "approved_by": "",
                    "expires_at_ms": now_ms() - 1000,  # already past
                }
            )
            expired = memory.expire_due()
            self.assertEqual(expired, ["mem_expire_1"])
            self.assertEqual(repo.get_memory("mem_expire_1")["status"], STATUS_EXPIRED)
            events = repo.list_memory_events(memory_id="mem_expire_1")
            self.assertTrue(any(e["event_type"] == "expired" for e in events))

    def test_quarantine_and_conflict_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, policy, memory, _ = _build(Path(tmp))
            base = {
                "layer": LAYER_PRODUCT_LONG_TERM,
                "namespace": memory.product_namespace("waf"),
                "retrieval_key": "r1",
                "content": "waf:false_positive:批次任务误报",
                "source_case_id": "",
                "scope": "waf:batch_fp",
                "trust_level": "medium",
                "status": STATUS_ACTIVE,
                "sensitivity_ok": True,
                "approved_by": "analyst-a",
                "expires_at_ms": now_ms() + 1000000,
            }
            repo.save_memory({**base, "memory_id": "mem_a"})
            repo.save_memory({**base, "memory_id": "mem_b"})  # duplicate content
            conflicts = memory.detect_conflicts("waf")
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(repo.get_memory("mem_b")["status"], STATUS_QUARANTINED)
            # direct quarantine
            memory.quarantine("mem_a", "analyst-b", "suspected_poisoning")
            self.assertEqual(repo.get_memory("mem_a")["status"], STATUS_QUARANTINED)
            self.assertEqual(repo.get_memory("mem_a")["trust_level"], "low")

    def test_archive_case_on_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, policy, memory, orchestrator = _build(Path(tmp))
            result = orchestrator.handle_alert(_waf_alert())
            short_term = repo.query_memory(layer=LAYER_CASE_SHORT_TERM, namespace=memory.case_namespace(result.case_id), limit=10)
            self.assertGreaterEqual(len(short_term), 1)
            archived = memory.archive_case(result.case_id)
            self.assertGreaterEqual(archived, 1)
            self.assertEqual(repo.get_memory(short_term[0]["memory_id"])["status"], STATUS_EXPIRED)


class MemoryGovernanceAPITest(unittest.TestCase):
    def test_gateway_state_memory_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)
            result = state.orchestrator.handle_alert(_waf_alert())

            # list filters by layer/status
            listed = state.list_memory({"layer": LAYER_PRODUCT_LONG_TERM, "status": STATUS_PENDING})
            self.assertGreaterEqual(len(listed), 1)
            self.assertEqual(listed[0]["status"], STATUS_PENDING)

            # promote via the API surface (missing gates → rejected)
            mem_id = listed[0]["memory_id"]
            res = state.promote_memory(mem_id, {"approved_by": "", "scope": "", "expires_at_ms": None})
            self.assertFalse(res["ok"])

            # sweep with conflict detection on the case product
            sweep = state.sweep_memory({"products": ["waf"]})
            self.assertIsInstance(sweep["expired"], list)

            # events traceable
            events = state.list_memory_events({"memory_id": mem_id})
            self.assertTrue(any(e["event_type"] == "rejected" for e in events))

    def test_confirm_alert_false_positive_writes_active_product_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)
            result = state.orchestrator.handle_alert(_waf_alert())
            detail = state.repo.get_case(result.case_id)
            alert_id = detail["linked_alerts"][0]["alert_id"]
            outcome = state.confirm_alert_false_positive(
                alert_id,
                {"analyst": "analyst-lee", "reason": "业务搜索参数误报"},
            )
            self.assertTrue(outcome["ok"])
            memory = state.repo.get_memory(outcome["memory_id"])
            self.assertEqual(memory["layer"], LAYER_PRODUCT_LONG_TERM)
            self.assertEqual(memory["status"], STATUS_ACTIVE)
            self.assertEqual(memory["trust_level"], "medium")
            content = json.loads(memory["content"])
            self.assertTrue(content["human_confirmed"])
            self.assertEqual(content["confirmation_type"], "business_false_positive")
            self.assertIn("rule_id", content["features"])
            self.assertGreaterEqual(len(content["features"]["similarity_features"]), 1)


if __name__ == "__main__":
    unittest.main()
