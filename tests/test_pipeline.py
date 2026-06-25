from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.log_adapter import LogAdapter, demo_rasp_profile
from defensive_ai_gateway.llm import GatewayLLM, LocalHeuristicLLM
from defensive_ai_gateway.memory import MemoryManager
from defensive_ai_gateway.models import RawAlert
from defensive_ai_gateway.normalizer import EventNormalizer
from defensive_ai_gateway.orchestrator import Orchestrator
from defensive_ai_gateway.policy import PolicyEngine
from defensive_ai_gateway.sample_alerts import generate_alert, generate_alerts


class PipelineTest(unittest.TestCase):
    def test_mapping_profile_dry_run_normalizes_real_rasp_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            adapter = LogAdapter(EventNormalizer(policy))
            profile = demo_rasp_profile()
            raw_log = {
                "metadata": {"id": "real-rasp-001"},
                "device": {"vendor": "bank-rasp", "type": "runtime_app_protection"},
                "risk": {"level": "高"},
                "time": "2026-06-25T10:00:00+08:00",
                "rule": {"id": "RASP-SQL-GUARD-221", "name": "SQL Injection Runtime Guard"},
                "host": {"name": "pay-api-01"},
                "http": {"client_ip": "10.1.2.3", "uri": "/openbanking/v2/payments/search", "method": "POST", "request_id": "req-001"},
                "app": {"name": "mobile-payment-api"},
                "rasp": {"action": "blocked_query_execution"},
                "sink": "JdbcTemplate.query",
                "taint": {"source": "request.parameter.beneficiaryName"},
                "stacktrace": "com.bank.PaymentSearchController.search\norg.springframework.jdbc.core.JdbcTemplate.query",
            }

            result = adapter.dry_run(profile, raw_log)

            self.assertTrue(result["ok"], result["errors"])
            self.assertEqual(result["raw_alert_preview"]["alert_id"], "real-rasp-001")
            self.assertEqual(result["raw_alert_preview"]["product"], "rasp")
            self.assertEqual(result["raw_alert_preview"]["severity"], "high")
            self.assertEqual(result["mapped_entities"]["src_ip"], "10.1.2.3")
            self.assertEqual(result["mapped_entities"]["host"], "pay-api-01")
            self.assertEqual(result["mapped_payload_fields"]["stack_trace"], raw_log["stacktrace"])
            self.assertEqual(result["raw_alert_preview"]["payload"]["host"], "pay-api-01")
            self.assertEqual(result["raw_alert_preview"]["payload"]["event_time"], raw_log["time"])
            self.assertEqual(result["raw_alert_preview"]["payload"]["stack_trace"], raw_log["stacktrace"])
            self.assertEqual(result["raw_alert_preview"]["payload"]["original_log"]["time"], raw_log["time"])
            normalized = result["normalized_event_preview"]
            self.assertEqual(normalized["product"], "rasp")
            self.assertEqual(normalized["entities"]["src_ip"], "10.1.2.3")
            self.assertEqual(normalized["entities"]["host"], "pay-api-01")
            evidence_types = {item["type"] for item in normalized["evidence"]}
            self.assertIn("rule_id", evidence_types)
            self.assertIn("stack_trace", evidence_types)
            self.assertIn("sink", evidence_types)

    def test_gateway_state_accepts_profile_mapped_alert_and_rejects_bad_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)
            raw_log = {
                "metadata": {"id": "real-rasp-002"},
                "device": {"vendor": "bank-rasp", "type": "runtime_app_protection"},
                "risk": {"level": "严重"},
                "time": "2026-06-25T10:10:00+08:00",
                "rule": {"id": "RASP-CMD-GUARD-118", "name": "Runtime Command Injection Guard"},
                "host": {"name": "internet-bank-02"},
                "http": {"client_ip": "10.9.8.7", "uri": "/login", "method": "GET"},
                "app": {"name": "internet-bank"},
                "rasp": {"action": "blocked_process_execution"},
                "sink": "java.lang.ProcessBuilder.start",
                "stacktrace": "com.bank.AuthController.login\njava.lang.ProcessBuilder.start",
            }

            alert = state.alert_from_payload({"profile_id": "demo-rasp-json", "log": raw_log})
            result = state.orchestrator.handle_alert(alert)

            self.assertEqual(alert.product, "rasp")
            self.assertEqual(alert.severity, "critical")
            self.assertEqual(result.agent, "rasp-agent")
            detail = state.repo.get_case(result.case_id)
            linked = detail["linked_alerts"][0]
            self.assertEqual(linked["raw_alert"]["payload"]["adapter"]["profile_id"], "demo-rasp-json")
            self.assertEqual(linked["normalized_event"]["entities"]["src_ip"], "10.9.8.7")
            self.assertEqual(linked["normalized_event"]["entities"]["host"], "internet-bank-02")

            with self.assertRaisesRegex(ValueError, "missing_required_field:alert_id"):
                state.alert_from_payload({"profile_id": "demo-rasp-json", "log": {"device": {"type": "runtime_app_protection"}}})

            dry_run = state.dry_run_mapping_profile({"profile_id": "demo-rasp-json", "log": {"device": {"type": "runtime_app_protection"}}})
            self.assertFalse(dry_run["ok"])
            self.assertIn("alert_id", dry_run["missing_required_fields"])
            self.assertIn("alert_id", dry_run["field_mapping_hints"])

    def test_auto_infer_mapping_profile_for_rasp_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)
            raw_log = {
                "metadata": {"id": "real-rasp-auto-001"},
                "device": {"vendor": "bank-rasp", "type": "runtime_app_protection"},
                "risk": {"level": "high"},
                "time": "2026-06-25T11:00:00+08:00",
                "rule": {"id": "RASP-SQL-GUARD-221", "name": "SQL Injection Runtime Guard"},
                "host": {"name": "pay-api-02"},
                "http": {"client_ip": "10.3.4.5", "uri": "/payments/search", "method": "POST", "request_id": "req-auto"},
                "app": {"name": "mobile-payment-api"},
                "rasp": {"action": "blocked_query_execution"},
                "sink": "JdbcTemplate.query",
                "taint": {"source": "request.parameter.keyword"},
                "stacktrace": "com.bank.PaymentSearchController.search\norg.springframework.jdbc.core.JdbcTemplate.query",
            }

            inferred = state.infer_mapping_profile({"log": raw_log})

            self.assertTrue(inferred["ok"], inferred)
            self.assertEqual(inferred["profile"]["mappings"]["alert_id"], "$.metadata.id")
            self.assertEqual(inferred["profile"]["mappings"]["product"], "$.device.type")
            self.assertEqual(inferred["profile"]["mappings"]["payload.stack_trace"], "$.stacktrace")
            self.assertEqual(inferred["required_missing"], [])
            field_targets = {field["target"] for field in inferred["fields"] if field["status"] == "mapped"}
            self.assertIn("payload.sink", field_targets)
            result = state.dry_run_mapping_profile({"profile": inferred["profile"], "log": raw_log})
            self.assertTrue(result["ok"], result["errors"])
            self.assertEqual(result["raw_alert_preview"]["product"], "rasp")
            self.assertEqual(result["raw_alert_preview"]["payload"]["host"], "pay-api-02")
            self.assertEqual(result["raw_alert_preview"]["payload"]["stack_trace"], raw_log["stacktrace"])

            incomplete = state.infer_mapping_profile({"log": {"device": {"type": "runtime_app_protection"}}})
            self.assertFalse(incomplete["ok"])
            self.assertIn("alert_id", incomplete["required_missing"])

    def test_waf_alert_creates_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            orchestrator = Orchestrator(repo, EventNormalizer(policy), MemoryManager(repo), LocalHeuristicLLM(), policy)
            payload = json.loads(Path("samples/waf_alert.json").read_text(encoding="utf-8"))
            alert = RawAlert(
                source=payload["source"],
                product=payload["product"],
                event_type=payload["event_type"],
                severity=payload["severity"],
                timestamp=payload["timestamp"],
                payload=payload["payload"],
                alert_id=payload["alert_id"],
            )
            result = orchestrator.handle_alert(alert)
            self.assertEqual(result.agent, "waf-agent")
            self.assertIn(result.classification, {"malicious", "suspicious", "insufficient_evidence"})
            self.assertTrue(result.explanation.get("verdict"))
            self.assertGreaterEqual(len(result.explanation.get("dimensions", [])), 1)
            self.assertEqual(repo.stats()["cases"], 1)
            cases = repo.list_cases()
            self.assertEqual(cases[0]["alert_count"], 1)
            self.assertEqual(cases[0]["latest_alert_id"], alert.alert_id)
            detail = repo.get_case(result.case_id)
            self.assertIsNotNone(detail)
            linked = detail["linked_alerts"]
            self.assertEqual(len(linked), 1)
            self.assertEqual(linked[0]["raw_alert"]["alert_id"], alert.alert_id)
            self.assertEqual(linked[0]["raw_alert"]["payload"]["method"], "POST")
            self.assertEqual(linked[0]["normalized_event"]["product"], "waf")
            self.assertGreaterEqual(len(linked[0]["normalized_event"]["evidence"]), 1)
            evidence_text = json.dumps(linked[0]["normalized_event"]["evidence"], ensure_ascii=False)
            self.assertNotIn("demo-secret-token", evidence_text)

    def test_llm_config_update_hides_key_and_rebuilds_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)
            updated = state.update_llm_config(
                {
                    "provider": "gateway",
                    "endpoint": "https://llm-gateway.internal/analyze",
                    "api_key": "secret-value",
                    "api_key_env": "BANK_LLM_KEY",
                    "model": "bank-sec-analyst",
                    "timeout_seconds": 45,
                }
            )
            self.assertEqual(updated["provider"], "gateway")
            self.assertEqual(updated["endpoint"], "https://llm-gateway.internal/analyze")
            self.assertEqual(updated["model"], "bank-sec-analyst")
            self.assertEqual(updated["timeout_seconds"], 45)
            self.assertTrue(updated["api_key_set"])
            self.assertNotIn("api_key", updated)
            self.assertIsInstance(state.llm, GatewayLLM)
            self.assertEqual(state.config.llm.api_key, "secret-value")

    def test_random_sample_generation_is_repeatable_and_varied(self):
        first = generate_alerts(3, product="waf", scenario="random", seed=42)
        second = generate_alerts(3, product="waf", scenario="random", seed=42)
        self.assertEqual(first, second)
        self.assertEqual({item["product"] for item in first}, {"waf"})
        self.assertGreater(len({item["alert_id"] for item in first}), 1)
        self.assertGreaterEqual(len({item["payload"]["rule_id"] for item in first}), 1)

    def test_suspicious_sample_generation_has_review_verdict(self):
        for product in ["waf", "hips", "rasp", "ndr", "siem"]:
            payload = generate_alert(product=product, scenario="suspicious", seed=10)
            assessment = payload["payload"]["evidence_assessment"]
            self.assertIn("需人工复核", assessment["expected_verdict"])
            self.assertGreaterEqual(len(assessment["analysis_dimensions"]), 1)
            self.assertIn(payload["severity"], {"medium", "high", "critical"})

    def test_active_false_positive_memory_downgrades_similar_waf_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            memory = MemoryManager(repo, policy)
            orchestrator = Orchestrator(repo, EventNormalizer(policy), memory, LocalHeuristicLLM(), policy)
            repo.save_memory(
                {
                    "memory_id": "mem_waf_fp_synthetic_search",
                    "layer": "product_long_term",
                    "namespace": memory.product_namespace("waf"),
                    "retrieval_key": "WAF-941-APP-ANOMALY",
                    "content": "false_positive: approved synthetic-browser traffic for /openbanking/v2/payments/search on mobile-payment-api",
                    "source_case_id": "case_prior_fp",
                    "scope": "waf:false_positive_pattern",
                    "trust_level": "medium",
                    "status": "active",
                    "sensitivity_ok": True,
                    "approved_by": "analyst-lee",
                    "expires_at_ms": None,
                }
            )
            payload = generate_alert(product="waf", scenario="false_positive", seed=1)
            alert = RawAlert(
                source=payload["source"],
                product=payload["product"],
                event_type=payload["event_type"],
                severity=payload["severity"],
                timestamp=payload["timestamp"],
                payload=payload["payload"],
                alert_id=payload["alert_id"],
            )
            result = orchestrator.handle_alert(alert)
            self.assertEqual(result.classification, "benign")
            self.assertIn("误报记忆", result.summary)
            self.assertTrue(any(item.get("title") == "历史误报" for item in result.explanation.get("dimensions", [])))
            self.assertTrue(any("复核" in action.action for action in result.recommended_actions))

    def test_similar_false_positive_memory_can_downgrade_suspicious_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            memory = MemoryManager(repo, policy)
            orchestrator = Orchestrator(repo, EventNormalizer(policy), memory, LocalHeuristicLLM(), policy)
            repo.save_memory(
                {
                    "memory_id": "mem_waf_fp_synthetic_search",
                    "layer": "product_long_term",
                    "namespace": memory.product_namespace("waf"),
                    "retrieval_key": "WAF-942-SQLI",
                    "content": (
                        "false_positive: approved similar review traffic for "
                        "/openbanking/v2/payments/search on mobile-payment-api; "
                        "rule_id=WAF-942-SQLI; parameter=beneficiaryName"
                    ),
                    "source_case_id": "case_prior_fp_review",
                    "scope": "waf:false_positive_pattern",
                    "trust_level": "medium",
                    "status": "active",
                    "sensitivity_ok": True,
                    "approved_by": "analyst-lee",
                    "expires_at_ms": None,
                }
            )
            payload = generate_alert(product="waf", scenario="suspicious", seed=10)
            alert = RawAlert(
                source=payload["source"],
                product=payload["product"],
                event_type=payload["event_type"],
                severity=payload["severity"],
                timestamp=payload["timestamp"],
                payload=payload["payload"],
                alert_id=payload["alert_id"],
            )
            result = orchestrator.handle_alert(alert)
            self.assertEqual(result.classification, "benign")
            self.assertIn("误报", result.explanation["verdict"])
            self.assertTrue(any(item.get("title") == "历史误报" for item in result.explanation.get("dimensions", [])))


if __name__ == "__main__":
    unittest.main()
