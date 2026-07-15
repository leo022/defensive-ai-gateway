from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from defensive_ai_gateway.config import GatewayConfig, MemoryMatchingConfig
from defensive_ai_gateway.database import Repository, SCHEMA_VERSION
from defensive_ai_gateway.llm import LLMClient
from defensive_ai_gateway.memory import MemoryManager
from defensive_ai_gateway.memory_matcher import MemoryMatcher
from defensive_ai_gateway.models import AgentResult, NormalizedEvent, RawAlert, now_ms
from defensive_ai_gateway.normalizer import EventNormalizer
from defensive_ai_gateway.orchestrator import Orchestrator
from defensive_ai_gateway.policy import PolicyEngine


def _event(product: str = "waf") -> NormalizedEvent:
    return NormalizedEvent(
        event_id="event-memory-match",
        source="test",
        product=product,
        event_type="web_attack_rule_hit",
        severity="high",
        timestamp="2026-07-13T00:00:00Z",
        entities={
            "rule": "WAF-123-SQLI",
            "app": "payment-api",
            "url": "/payments/982731/search?mode=batch",
            "src_ip": "10.1.2.3",
        },
        evidence=[
            {"type": "user_agent", "value": "synthetic-browser/4.2", "ref": "ref-1"},
            {"type": "matched_parameters", "value": ["beneficiaryName"], "ref": "ref-2"},
        ],
        sensitivity_tags=[],
        raw_ref="alert-memory-match",
    )


def _memory(
    memory_id: str = "mem-approved-waf",
    product: str = "waf",
    trust_level: str = "medium",
    expires_at_ms: int | None = None,
) -> dict:
    content = {
        "classification": "benign",
        "false_positive_candidate": True,
        "human_confirmed": True,
        "product": product,
        "event_type": "web_attack_rule_hit",
        "features": {
            "product": product,
            "event_type": "web_attack_rule_hit",
            "rule_id": "WAF-123-SQLI",
            "app": "payment-api",
            "uri": "/payments/{id}/search",
            "user_agent": "synthetic-browser/4.2",
        },
    }
    return {
        "memory_id": memory_id,
        "layer": "product_long_term",
        "namespace": f"product/{product}",
        "retrieval_key": "WAF-123-SQLI",
        "content": json.dumps(content, ensure_ascii=False, sort_keys=True),
        "source_case_id": "case-approved",
        "scope": f"{product}:business_false_positive:web_attack_rule_hit",
        "trust_level": trust_level,
        "status": "active",
        "sensitivity_ok": True,
        "approved_by": "analyst-lee",
        "expires_at_ms": expires_at_ms if expires_at_ms is not None else now_ms() + 30 * 24 * 3600 * 1000,
    }


class _CapturingLLM(LLMClient):
    def __init__(self, classification: str = "suspicious"):
        self.classification = classification
        self.context: dict = {}

    def analyze(self, prompt: str, context: dict) -> dict:
        self.context = context
        verdict = "【真实攻击】- test" if self.classification == "malicious" else "【需人工复核】- test"
        return {
            "classification": self.classification,
            "confidence": 0.84,
            "verdict": verdict,
            "reason": f"研判结论：{verdict}\n分析报告：\n- 规则匹配：test",
            "analysis_dimensions": [{"title": "规则匹配", "status": "review", "evidence": "test"}],
            "recommended_next_steps": ["read-only review"],
            "missing_evidence": [],
            "business_impact": "test",
        }


class MemoryMatcherUnitTest(unittest.TestCase):
    def test_hybrid_score_matches_structured_fields_and_path_template(self):
        matcher = MemoryMatcher()
        evaluation = matcher.match(_event(), [_memory()])
        self.assertEqual(evaluation.best_memory_id, "mem-approved-waf")
        best = evaluation.best
        self.assertIsNotNone(best)
        self.assertGreaterEqual(best.structured_score, 0.9)
        self.assertEqual(best.score_breakdown["rule_id"], 1.0)
        self.assertGreater(best.semantic_score, 0)
        self.assertEqual(best.retrieval_score, 1.0)
        self.assertGreaterEqual(best.overall_score, matcher.config.apply_threshold)
        self.assertIn("uri:/payments/{id}/search", best.matched_features)

    def test_hard_filters_reject_untrusted_expired_and_cross_product_memory(self):
        matcher = MemoryMatcher()
        low = _memory("mem-low", trust_level="low")
        expired = _memory("mem-expired", expires_at_ms=now_ms() - 1)
        cross_product = _memory("mem-ndr", product="ndr")
        evaluation = matcher.match(_event(), [low, expired, cross_product])
        self.assertEqual(evaluation.candidates, [])
        self.assertEqual(evaluation.final_effect, "none")

    def test_scope_and_match_policy_are_enforced_and_non_fp_knowledge_is_ignored(self):
        matcher = MemoryMatcher()
        wrong_scope = _memory("mem-wrong-scope")
        wrong_scope["scope"] = "waf:business_false_positive:different_event"

        wrong_policy = _memory("mem-wrong-policy")
        content = json.loads(wrong_policy["content"])
        content["features"]["rule_id"] = "WAF-DIFFERENT"
        content["match_policy"] = {"must_match_all": ["rule_id"]}
        wrong_policy["content"] = json.dumps(content, ensure_ascii=False, sort_keys=True)

        knowledge = _memory("mem-attack-knowledge")
        content = json.loads(knowledge["content"])
        content.update({"classification": "malicious", "human_confirmed": False, "false_positive_candidate": False})
        content["summary"] = "approved attack handling knowledge"
        knowledge["content"] = json.dumps(content, ensure_ascii=False, sort_keys=True)

        evaluation = matcher.match(_event(), [wrong_scope, wrong_policy, knowledge])
        self.assertEqual(evaluation.candidates, [])

    def test_current_attack_evidence_has_memory_downgrade_veto(self):
        matcher = MemoryMatcher()
        event = _event()
        event.entities["action"] = "blocked"
        event.evidence.extend(
            [
                {"type": "sink", "value": "ProcessBuilder.start", "ref": "ref-sink"},
                {"type": "stack_trace", "value": "Controller -> ProcessBuilder.start", "ref": "ref-stack"},
            ]
        )
        evaluation = matcher.match(event, [_memory()])
        result = AgentResult(
            case_id="case-1",
            agent="waf-agent",
            classification="malicious",
            confidence=0.91,
            severity="high",
            summary="attack",
            evidence=[],
            missing_evidence=[],
            recommended_actions=[],
            dashboard_cards=[],
            explanation={"verdict": "【真实攻击】- SQL injection", "dimensions": []},
        )
        reconciled = matcher.reconcile(result, evaluation)
        self.assertEqual(reconciled.classification, "malicious")
        self.assertEqual(evaluation.final_effect, "attack_signal_veto")
        self.assertIn("不覆盖", reconciled.explanation["verdict"])

    def test_waf_union_select_cannot_be_downgraded_by_similar_false_positive_memory(self):
        matcher = MemoryMatcher()
        event = _event()
        event.evidence.append(
            {
                "type": "payload_category",
                "value": "SQL injection with UNION SELECT",
                "ref": "ref-current-waf-payload",
            }
        )
        evaluation = matcher.match(event, [_memory()])
        self.assertIsNotNone(evaluation.best)
        self.assertGreaterEqual(evaluation.best.overall_score, evaluation.best.apply_threshold)
        self.assertTrue(evaluation.attack_signal_veto)
        self.assertIn("explicit_payload_category", evaluation.attack_signal_reasons)

        result = AgentResult(
            case_id="case-waf-sqli",
            agent="waf-agent",
            classification="malicious",
            confidence=0.93,
            severity="high",
            summary="current SQL injection attack",
            evidence=[],
            missing_evidence=[],
            recommended_actions=[],
            dashboard_cards=[],
            explanation={"verdict": "【真实攻击】- SQL injection", "dimensions": []},
        )
        reconciled = matcher.reconcile(result, evaluation)
        self.assertEqual(reconciled.classification, "malicious")
        self.assertEqual(evaluation.final_effect, "attack_signal_veto")

    def test_common_current_web_attack_shapes_veto_memory_downgrade(self):
        matcher = MemoryMatcher()
        cases = (
            ("payload_category", "<script>document.cookie</script>"),
            ("command_line", "status=ok; /bin/sh -c id"),
            ("uri", "/download/../../etc/passwd"),
        )
        for evidence_type, value in cases:
            with self.subTest(evidence_type=evidence_type, value=value):
                event = _event()
                event.evidence.append({"type": evidence_type, "value": value, "ref": "ref-current"})
                evaluation = matcher.match(event, [_memory()])
                self.assertTrue(evaluation.attack_signal_veto)
                self.assertIn(f"explicit_{evidence_type}", evaluation.attack_signal_reasons)

    def test_historical_correlation_attack_text_does_not_veto_current_alert(self):
        matcher = MemoryMatcher()
        event = _event()
        event.evidence.append(
            {
                "type": "correlation",
                "value": {
                    "historical_case": "SQL injection with UNION SELECT",
                    "current_request": "no exploit payload observed",
                },
                "ref": "ref-historical-correlation",
            }
        )
        evaluation = matcher.match(event, [_memory()])
        self.assertFalse(evaluation.attack_signal_veto)
        self.assertEqual(evaluation.attack_signal_reasons, [])


class MemoryMatcherIntegrationTest(unittest.TestCase):
    def _build(self, tmp: str, classification: str = "suspicious"):
        config = GatewayConfig()
        repo = Repository(str(Path(tmp) / "gateway.db"))
        policy = PolicyEngine(config.policy)
        memory = MemoryManager(repo, policy)
        repo.save_memory(_memory())
        llm = _CapturingLLM(classification)
        matcher = MemoryMatcher(MemoryMatchingConfig(candidate_limit=100, top_k=5))
        orchestrator = Orchestrator(repo, EventNormalizer(policy), memory, llm, policy, memory_matcher=matcher)
        return repo, llm, orchestrator

    @staticmethod
    def _alert(alert_id: str = "alert-provider-neutral") -> RawAlert:
        return RawAlert(
            source="test",
            product="waf",
            event_type="web_attack_rule_hit",
            severity="high",
            timestamp="2026-07-13T00:00:00Z",
            payload={
                "rule_id": "WAF-123-SQLI",
                "app": "payment-api",
                "uri": "/payments/982731/search?mode=batch",
                "src_ip": "10.1.2.3",
                "headers": {"user-agent": "synthetic-browser/4.2"},
            },
            alert_id=alert_id,
        )

    def test_provider_neutral_match_is_injected_reconciled_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, llm, orchestrator = self._build(tmp)
            result = orchestrator.handle_alert(self._alert())

            self.assertEqual(result.classification, "benign")
            self.assertIn("误报记忆关联", result.summary)
            self.assertEqual(result.explanation["memory_association"]["final_effect"], "downgraded_to_benign")
            self.assertEqual(len(llm.context["memory"]["product_long_term"]), 1)
            self.assertEqual(llm.context["memory"]["memory_association"]["best_memory_id"], "mem-approved-waf")

            matches = repo.list_memory_matches(case_id=result.case_id)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["memory_id"], "mem-approved-waf")
            self.assertEqual(matches[0]["decision"], "downgraded_to_benign")
            self.assertEqual(matches[0]["final_effect"], "downgraded_to_benign")
            self.assertGreaterEqual(matches[0]["overall_score"], 0.78)
            detail = repo.get_case(result.case_id)
            self.assertEqual(detail["memory_matches"][0]["match_id"], matches[0]["match_id"])

    def test_model_label_alone_cannot_trigger_attack_veto(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, orchestrator = self._build(tmp, classification="malicious")
            result = orchestrator.handle_alert(self._alert("alert-provider-malicious"))
            self.assertEqual(result.classification, "benign")
            matches = repo.list_memory_matches(case_id=result.case_id)
            self.assertEqual(matches[0]["decision"], "downgraded_to_benign")

    def test_schema_migrates_to_memory_match_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            version = repo.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            self.assertEqual(version, SCHEMA_VERSION)
            columns = {row["name"] for row in repo.conn.execute("PRAGMA table_info(memory_matches)").fetchall()}
            self.assertIn("score_breakdown_json", columns)


if __name__ == "__main__":
    unittest.main()
