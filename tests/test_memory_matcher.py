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


def _rasp_read_file_memory() -> dict:
    content = {
        "classification": "benign",
        "false_positive_candidate": True,
        "human_confirmed": True,
        "confirmation_type": "business_false_positive",
        "product": "rasp",
        "event_type": "高危读取行为判断",
        "features": {
            "product": "rasp",
            "event_type": "高危读取行为判断",
            "rule_id": "cloudrasp_read_file_103",
            "app": "ai_agent",
            "host": "VM-0-7-centos",
            "method": "GET",
            "uri": "http://106.53.107.29:8080/bastestground/file/file_input_stream/getParam",
            "src_ip": "43.154.138.159",
        },
        "match_policy": {
            "must_match_any": ["product", "event_type", "rule_id"],
            "high_similarity_threshold": 0.78,
            "effect_mode": "downgrade_to_benign",
        },
    }
    return {
        "memory_id": "mem-approved-rasp-read-file",
        "layer": "product_long_term",
        "namespace": "product/rasp",
        "retrieval_key": "cloudrasp_read_file_103",
        "content": json.dumps(content, ensure_ascii=False, sort_keys=True),
        "source_case_id": "case_rasp_source",
        "scope": "rasp:business_false_positive:高危读取行为判断",
        "trust_level": "medium",
        "status": "active",
        "sensitivity_ok": True,
        "approved_by": "analyst",
        "expires_at_ms": now_ms() + 30 * 24 * 3600 * 1000,
    }


def _rasp_read_file_event(*, method: str, uri: str, host: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"event-{method.lower()}-{uri.rsplit('/', 1)[-1]}",
        source="syslog",
        product="rasp",
        event_type="高危读取行为判断",
        severity="critical",
        timestamp="2026-07-30T07:38:38Z",
        entities={
            "rule": "cloudrasp_read_file_103",
            "app": "ai_agent",
            "host": host,
            "method": method,
            "url": uri,
            "src_ip": "43.154.138.159",
            "action": "log",
        },
        evidence=[
            {"type": "sink", "value": "java.io.FileInputStream.<init>", "ref": "ref-sink"},
            {"type": "stack_trace", "value": ["java.io.FileInputStream.<init>"], "ref": "ref-stack"},
        ],
        sensitivity_tags=[],
        raw_ref=f"alert-{method.lower()}-{uri.rsplit('/', 1)[-1]}",
    )


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
        self.assertEqual(best.match_level, "exact")
        self.assertTrue(best.title_eligible)

    def test_sparse_memory_cannot_become_high_confidence(self):
        matcher = MemoryMatcher()
        sparse = _memory("mem-sparse")
        content = json.loads(sparse["content"])
        content.pop("event_type", None)
        content["features"] = {
            "rule_id": "WAF-123-SQLI",
            "uri": "/payments/{id}/search",
        }
        sparse["content"] = json.dumps(content, ensure_ascii=False, sort_keys=True)

        evaluation = matcher.match(_event(), [sparse])

        self.assertIsNotNone(evaluation.best)
        self.assertGreaterEqual(evaluation.best.overall_score, matcher.config.apply_threshold)
        self.assertEqual(evaluation.best.match_level, "related")
        self.assertFalse(evaluation.best.title_eligible)
        self.assertIn("insufficient_feature_coverage", evaluation.best.comparison["gate_reasons"])

    def test_retrieval_key_requires_exact_field_match(self):
        matcher = MemoryMatcher()
        memory = _memory("mem-substring-retrieval")
        memory["retrieval_key"] = "123"

        evaluation = matcher.match(_event(), [memory])

        self.assertIsNotNone(evaluation.best)
        self.assertEqual(evaluation.best.retrieval_score, 0.0)
        self.assertEqual(evaluation.best.comparison["retrieval_match_fields"], [])
        self.assertLess(evaluation.best.overall_score, matcher.config.apply_threshold)
        self.assertEqual(evaluation.best.match_level, "related")
        self.assertFalse(evaluation.best.title_eligible)

    def test_enabled_apply_uses_memory_confidence_when_direction_changes(self):
        matcher = MemoryMatcher(MemoryMatchingConfig(apply_enabled=True))
        evaluation = matcher.match(_event(), [_memory()])
        result = AgentResult(
            case_id="case-confidence",
            agent="waf-agent",
            classification="suspicious",
            confidence=0.99,
            severity="critical",
            summary="review",
            evidence=[],
            missing_evidence=[],
            recommended_actions=[],
            dashboard_cards=[],
            explanation={"verdict": "【需人工复核】- test", "dimensions": []},
        )

        reconciled = matcher.reconcile(result, evaluation)

        self.assertEqual(reconciled.classification, "benign")
        self.assertEqual(evaluation.final_effect, "downgraded_to_benign")
        self.assertLess(reconciled.confidence, 0.99)
        self.assertEqual(
            reconciled.confidence,
            reconciled.explanation["memory_association"]["memory_confidence"],
        )

    def test_rasp_method_and_uri_boundaries_control_title_eligibility(self):
        matcher = MemoryMatcher()
        memory = _rasp_read_file_memory()
        source_uri = "http://106.53.107.29:8080/bastestground/file/file_input_stream/getParam"
        scenarios = (
            (
                "same_method_and_uri",
                _rasp_read_file_event(method="GET", uri=source_uri, host="106.53.107.29:8080"),
                "high",
                True,
                ["host"],
            ),
            (
                "post_parameter_route",
                _rasp_read_file_event(
                    method="POST",
                    uri="http://106.53.107.29:8080/bastestground/file/file_input_stream/postParam",
                    host="106.53.107.29:8080",
                ),
                "related",
                False,
                ["host", "method", "uri"],
            ),
            (
                "different_jstl_call_path",
                _rasp_read_file_event(
                    method="GET",
                    uri="http://106.53.107.29:8080/bastestground/jstl-import/index.jsp",
                    host="VM-0-7-centos",
                ),
                "related",
                False,
                ["uri"],
            ),
        )
        for name, event, expected_level, title_eligible, conflicts in scenarios:
            with self.subTest(name=name):
                evaluation = matcher.match(event, [memory])
                self.assertIsNotNone(evaluation.best)
                self.assertEqual(evaluation.best.match_level, expected_level)
                self.assertEqual(evaluation.best.title_eligible, title_eligible)
                self.assertEqual(
                    set(evaluation.best.comparison["conflicting_fields"]),
                    set(conflicts),
                )

                result = AgentResult(
                    case_id=f"case-{name}",
                    agent="rasp-agent",
                    classification="suspicious",
                    confidence=0.85,
                    severity="critical",
                    summary=f"summary-{name}",
                    evidence=[],
                    missing_evidence=[],
                    recommended_actions=[],
                    dashboard_cards=[],
                    explanation={"verdict": "【需人工复核】- test", "dimensions": []},
                )
                reconciled = matcher.reconcile(result, evaluation)
                self.assertEqual(
                    reconciled.summary.startswith("【长期记忆命中】"),
                    title_eligible,
                )
                history = reconciled.explanation["dimensions"][-1]["evidence"]
                expected_label = {
                    "high": "高度相似",
                    "related": "部分相似（不构成命中）",
                }[expected_level]
                self.assertIn(f"匹配程度：{expected_label}", history)
                if not title_eligible:
                    self.assertEqual(evaluation.final_effect, "related_only")
                    self.assertIn("不构成命中", reconciled.explanation["verdict"])

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

    def test_provider_neutral_match_is_evaluated_after_model_and_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, llm, orchestrator = self._build(tmp)
            result = orchestrator.handle_alert(self._alert())

            self.assertEqual(result.classification, "suspicious")
            self.assertIn("长期记忆命中", result.summary)
            self.assertEqual(result.explanation["memory_association"]["final_effect"], "apply_disabled_review")
            self.assertIn(
                result.explanation["memory_association"]["matches"][0]["match_level"],
                {"exact", "high"},
            )
            self.assertTrue(result.explanation["memory_association"]["matches"][0]["title_eligible"])
            self.assertEqual(llm.context["memory"]["product_long_term"], [])
            self.assertEqual(llm.context["memory"]["memory_association"]["best_memory_id"], "")
            self.assertTrue(llm.context["memory"]["memory_association"]["deferred_to_policy"])

            matches = repo.list_memory_matches(case_id=result.case_id)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["memory_id"], "mem-approved-waf")
            self.assertEqual(matches[0]["decision"], "apply_disabled_review")
            self.assertEqual(matches[0]["final_effect"], "apply_disabled_review")
            self.assertTrue(matches[0]["selected_candidate"])
            self.assertTrue(matches[0]["title_eligible"])
            self.assertEqual(matches[0]["match_level"], "exact")
            self.assertEqual(matches[0]["config_snapshot"]["semantic_method"], "signed_lexical_hash_v1")
            self.assertGreaterEqual(matches[0]["overall_score"], 0.78)
            detail = repo.get_case(result.case_id)
            self.assertEqual(detail["memory_matches"][0]["match_id"], matches[0]["match_id"])

    def test_model_label_alone_cannot_trigger_attack_veto(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, orchestrator = self._build(tmp, classification="malicious")
            result = orchestrator.handle_alert(self._alert("alert-provider-malicious"))
            self.assertEqual(result.classification, "malicious")
            self.assertEqual(
                result.explanation["memory_association"]["final_effect"],
                "malicious_requires_review",
            )
            matches = repo.list_memory_matches(case_id=result.case_id)
            self.assertEqual(matches[0]["decision"], "malicious_requires_review")

    def test_exact_lookup_key_is_prioritized_ahead_of_newer_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            older_exact = _memory("memory-older-exact")
            newer_other = _memory("memory-newer-other")
            older_exact["retrieval_key"] = "WAF-EXACT-LOOKUP"
            newer_other["retrieval_key"] = "WAF-OTHER"
            repo.save_memory(older_exact)
            repo.save_memory(newer_other)
            repo.conn.execute(
                "UPDATE memory_entries SET updated_at_ms = 1 WHERE memory_id = ?",
                (older_exact["memory_id"],),
            )
            repo.conn.execute(
                "UPDATE memory_entries SET updated_at_ms = 2 WHERE memory_id = ?",
                (newer_other["memory_id"],),
            )
            repo.conn.commit()

            candidates = repo.query_matchable_product_memory(
                "waf",
                now_ms(),
                limit=1,
                lookup_keys=["waf-exact-lookup"],
            )

            self.assertEqual([item["memory_id"] for item in candidates], ["memory-older-exact"])

    def test_schema_migrates_to_memory_match_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            version = repo.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            self.assertEqual(version, SCHEMA_VERSION)
            columns = {row["name"] for row in repo.conn.execute("PRAGMA table_info(memory_matches)").fetchall()}
            self.assertIn("score_breakdown_json", columns)
            self.assertIn("comparison_json", columns)
            self.assertIn("config_snapshot_json", columns)

    def test_v18_match_history_migrates_without_overwriting_future_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gateway.db"
            repo = Repository(str(path))
            repo.conn.executescript(
                """
                DROP TABLE memory_matches;
                CREATE TABLE memory_matches (
                  match_id TEXT PRIMARY KEY,
                  event_id TEXT NOT NULL,
                  alert_id TEXT NOT NULL,
                  case_id TEXT NOT NULL,
                  analysis_run_id TEXT NOT NULL,
                  memory_id TEXT NOT NULL,
                  matcher_version TEXT NOT NULL,
                  rank INTEGER NOT NULL,
                  structured_score REAL NOT NULL,
                  semantic_score REAL NOT NULL,
                  retrieval_score REAL NOT NULL,
                  overall_score REAL NOT NULL,
                  decision TEXT NOT NULL,
                  final_effect TEXT NOT NULL,
                  matched_features_json TEXT NOT NULL,
                  score_breakdown_json TEXT NOT NULL,
                  created_at_ms INTEGER NOT NULL,
                  UNIQUE (event_id, memory_id)
                );
                INSERT INTO memory_matches VALUES
                  ('mm-legacy', 'event-legacy', 'alert-legacy', 'case-legacy',
                   'run-legacy', 'memory-legacy', 'hybrid-memory-v4', 1,
                   0.8, 0.4, 1.0, 0.732, 'review_only', 'review_only',
                   '[]', '{}', 1);
                DELETE FROM schema_version;
                INSERT INTO schema_version(version, applied_at_ms) VALUES (18, 1);
                """
            )
            repo.conn.close()

            migrated = Repository(str(path))
            migrated.insert_memory_matches(
                event_id="event-legacy",
                alert_id="alert-legacy",
                case_id="case-legacy",
                analysis_run_id="run-new",
                matcher_version="hybrid-memory-v5",
                final_effect="apply_disabled_review",
                candidates=[
                    {
                        "memory_id": "memory-legacy",
                        "rank": 1,
                        "structured_score": 0.9,
                        "semantic_score": 0.5,
                        "retrieval_score": 1.0,
                        "overall_score": 0.82,
                        "decision": "apply_disabled_review",
                        "match_level": "high",
                        "title_eligible": True,
                    }
                ],
                selected_memory_id="memory-legacy",
            )

            history = migrated.list_memory_matches(event_id="event-legacy")
            self.assertEqual(len(history), 2)
            legacy = next(item for item in history if item["analysis_run_id"] == "run-legacy")
            current = next(item for item in history if item["analysis_run_id"] == "run-new")
            self.assertEqual(legacy["match_level"], "legacy")
            self.assertEqual(legacy["config_snapshot"], {})
            self.assertTrue(current["selected_candidate"])
            self.assertEqual(current["final_effect"], "apply_disabled_review")


if __name__ == "__main__":
    unittest.main()
