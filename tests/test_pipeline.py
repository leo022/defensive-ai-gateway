from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.log_adapter import LogAdapter, demo_rasp_profile, mapping_profile_record
from defensive_ai_gateway.llm import GatewayLLM, LLMClient, LocalHeuristicLLM
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

    def test_auto_infer_real_rasp_event_items_format_derives_sink(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = GatewayConfig()
        config.database.path = str(Path(tmp.name) / "gateway.db")
        state = GatewayState(config)
        raw_log = {
            "data_type": "attack_event",
            "event": {
                "request_id": "3b585cb05d3e4610ab2b2ab68e131eea",
                "attack_time": "2025-10-16T09:17:20+08:00",
                "created_at": "2025-10-16T11:19:23.064+08:00",
                "app_name": "cloudrasp-vulns",
                "path": "/cloudrasp-vulns/deserialization/fastjson/postBody",
                "attack_source": "10.0.10.132",
                "server_hostname": "localhost.localdomain",
                "request_message": {
                    "method": "POST",
                    "url": "http://192.168.15.93:8080/cloudrasp-vulns/deserialization/fastjson/postBody",
                },
            },
            "items": [
                {
                    "rule_id": "cloudrasp_jndi_108",
                    "rule_name": "请求触发 JNDI 连接判断",
                    "attack_type": "jndi",
                    "attack_level": 1,
                    "intercept_state": "log",
                    "hook_data": {"url": "ldap://127.0.0.1:1389/obj"},
                    "stacktrace": [
                        "com.sun.jndi.toolkit.url.GenericURLContext.lookup(GenericURLContext.java)",
                        "javax.naming.InitialContext.lookup(InitialContext.java:417)",
                        "com.sun.rowset.JdbcRowSetImpl.connect(JdbcRowSetImpl.java:624)",
                    ],
                }
            ],
        }

        inferred = state.infer_mapping_profile({"log": raw_log})

        self.assertTrue(inferred["ok"], inferred)
        self.assertEqual(inferred["profile"]["mappings"]["alert_id"], "$.event.request_id")
        self.assertEqual(inferred["profile"]["mappings"]["severity"], "$.items[0].attack_level")
        self.assertEqual(inferred["profile"]["mappings"]["payload.stack_trace"], "$.items[0].stacktrace")
        self.assertNotIn("sink", inferred["recommended_missing"])
        self.assertEqual(
            inferred["profile"]["mappings"]["payload.sink"],
            {"path": "$.items[0].stacktrace", "transform": "rasp_sink_from_stacktrace"},
        )

        result = state.dry_run_mapping_profile({"profile": inferred["profile"], "log": raw_log})
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["raw_alert_preview"]["severity"], "critical")
        self.assertEqual(result["raw_alert_preview"]["payload"]["sink"], "com.sun.jndi.toolkit.url.GenericURLContext.lookup")
        self.assertEqual(result["mapped_entities"]["src_ip"], "10.0.10.132")

        demo_result = state.dry_run_mapping_profile({"profile": demo_rasp_profile().to_dict(), "log": raw_log})
        self.assertTrue(demo_result["ok"], demo_result["errors"])
        self.assertEqual(demo_result["raw_alert_preview"]["payload"]["sink"], "com.sun.jndi.toolkit.url.GenericURLContext.lookup")

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

    def test_random_rasp_generation_covers_real_attack_event_shapes(self):
        alerts = [generate_alert(product="rasp", scenario="attack", seed=seed) for seed in range(1, 12)]
        attack_types = {alert["payload"]["items"][0]["attack_type"] for alert in alerts}

        self.assertGreaterEqual({"jndi", "sql_injection", "command_execution"}, attack_types)
        for alert in alerts:
            payload = alert["payload"]
            raw_log = payload["raw_rasp_log"]
            self.assertEqual(raw_log["data_type"], "attack_event")
            self.assertEqual(raw_log["event"]["request_id"], payload["event"]["request_id"])
            self.assertEqual(raw_log["items"][0]["rule_id"], payload["rule_id"])
            self.assertIn("hook_data", raw_log["items"][0])
            self.assertIn("stacktrace", raw_log["items"][0])

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


class ModelReconciliationTest(unittest.TestCase):
    """Model-backed LLMs (ollama/gateway) must produce logically consistent
    results even when the small local model returns a verdict contradicted by
    all-``info`` dimensions or misclassifies a sample."""

    class _FakeModelLLM(LLMClient):
        is_deterministic = False

        def __init__(self, result: dict):
            self._result = result

        def analyze(self, prompt, context):
            return dict(self._result)

    def _state_with_llm(self, tmp, llm):
        config = GatewayConfig()
        config.database.path = str(Path(tmp) / "gateway.db")
        state = GatewayState(config)
        state.orchestrator.llm = llm  # inject the fake model LLM
        return state

    def _alert_from_sample(self, payload):
        return RawAlert(
            source=payload["source"],
            product=payload["product"],
            event_type=payload["event_type"],
            severity=payload["severity"],
            timestamp=payload["timestamp"],
            payload=payload["payload"],
            alert_id=payload["alert_id"],
        )

    def _weak_malicious_result(self):
        return {
            "classification": "malicious",
            "confidence": 0.95,
            "verdict": "【真实攻击】- malicious",
            "reason": "Fastjson vulnerability detected.",
            "analysis_dimensions": [
                {"title": "Vulnerability", "status": "info", "evidence": "Fastjson"},
                {"title": "Attack Type", "status": "info", "evidence": "RCE"},
            ],
            "business_impact": "High",
            "missing_evidence": [],
            "recommended_next_steps": [],
        }

    def test_sample_false_positive_overrides_wrong_model_malicious(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state_with_llm(tmp, self._FakeModelLLM(self._weak_malicious_result()))
            payload = generate_alert(product="rasp", scenario="false_positive", seed=5003)
            result = state.orchestrator.handle_alert(self._alert_from_sample(payload))
            # Structured sample ground truth wins over the model's malicious call.
            self.assertEqual(result.classification, "benign")
            self.assertIn("误报", result.explanation["verdict"])
            statuses = {d["status"] for d in result.explanation.get("dimensions", [])}
            self.assertTrue(statuses <= {"benign", "normal", "review"})
            self.assertNotIn("risk", statuses)

    def test_non_sample_keeps_classification_but_synthesizes_consistent_dims(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state_with_llm(tmp, self._FakeModelLLM(self._weak_malicious_result()))
            payload = json.loads(Path("samples/rasp_alert.json").read_text(encoding="utf-8"))
            result = state.orchestrator.handle_alert(state.alert_from_payload(payload))
            # No structured ground truth: model classification is kept (real JNDI
            # attack), but all-info dimensions must be replaced with risk dims.
            self.assertEqual(result.classification, "malicious")
            dims = result.explanation.get("dimensions", [])
            self.assertGreaterEqual(len(dims), 1)
            self.assertTrue(any(d["status"] in {"risk", "blocked"} for d in dims),
                            f"expected a risk/blocked dimension, got {dims}")
            self.assertFalse(all(d["status"] == "info" for d in dims))

    def test_consistent_model_result_is_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            consistent = self._weak_malicious_result()
            consistent["analysis_dimensions"] = [
                {"title": "请求特征", "status": "risk", "evidence": "JNDI lookup to ldap sink"},
                {"title": "处置动作", "status": "blocked", "evidence": "RASP blocked"},
            ]
            state = self._state_with_llm(tmp, self._FakeModelLLM(consistent))
            payload = json.loads(Path("samples/rasp_alert.json").read_text(encoding="utf-8"))
            result = state.orchestrator.handle_alert(state.alert_from_payload(payload))
            self.assertEqual(result.classification, "malicious")
            titles = {d["title"] for d in result.explanation["dimensions"]}
            self.assertIn("请求特征", titles)


class AlertProductRoutingTest(unittest.TestCase):
    """Raw vendor-format logs without ?profile= must not silently default to siem."""

    def _state(self, tmp) -> GatewayState:
        config = GatewayConfig()
        config.database.path = str(Path(tmp) / "gateway.db")
        return GatewayState(config)

    def _cloudrasp_log(self) -> dict:
        path = Path(__file__).parent.parent / "samples_syslog" / "rasp" / "rasp_alert.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_raw_cloudrasp_log_without_profile_detected_as_rasp(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            alert = state.alert_from_payload(self._cloudrasp_log())
            self.assertEqual(alert.product, "rasp")  # not "siem"
            # no auto-rasp-json registered in temp DB -> shallow build, no adapter
            self.assertNotIn("adapter", alert.payload)

    def test_raw_vendor_log_auto_applies_registered_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            # register auto-rasp-json profile (reuse demo mappings, which cover cloudcrasp)
            profile = demo_rasp_profile()
            profile.profile_id = "auto-rasp-json"
            state.repo.save_mapping_profile(mapping_profile_record(profile))

            alert = state.alert_from_payload(self._cloudrasp_log())
            self.assertEqual(alert.product, "rasp")
            self.assertEqual(alert.payload["adapter"]["profile_id"], "auto-rasp-json")
            entities = alert.payload["mapped_entities"]
            self.assertEqual(entities["rule"], "cloudrasp_jndi_108")
            self.assertEqual(entities["src_ip"], "10.0.10.132")

    def test_unrecognizable_log_without_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            with self.assertRaisesRegex(ValueError, "无法识别"):
                state.alert_from_payload({"foo": "bar", "nested": {"x": 1}})

    def test_standard_alert_without_product_defaults_to_siem(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            alert = state.alert_from_payload({"event_type": "scan", "severity": "high"})
            self.assertEqual(alert.product, "siem")

    def test_standard_alert_with_explicit_product_is_not_auto_profiled(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            # register an auto profile for rasp to prove it is NOT used for explicit products
            profile = demo_rasp_profile()
            profile.profile_id = "auto-rasp-json"
            state.repo.save_mapping_profile(mapping_profile_record(profile))
            alert = state.alert_from_payload(
                {"product": "waf", "event_type": "sqli", "severity": "high", "payload": {"uri": "/x"}}
            )
            self.assertEqual(alert.product, "waf")
            self.assertNotIn("adapter", alert.payload)


if __name__ == "__main__":
    unittest.main()
