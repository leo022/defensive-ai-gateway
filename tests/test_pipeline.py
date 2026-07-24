from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.log_adapter import LogAdapter, MappingProfile, demo_rasp_profile, mapping_profile_record
from defensive_ai_gateway.llm import GatewayLLM, LLMClient, LocalHeuristicLLM, _parse_json_object
from defensive_ai_gateway.memory import MemoryManager
from defensive_ai_gateway.models import AgentResult, RawAlert, RecommendedAction
from defensive_ai_gateway.normalizer import EventNormalizer
from defensive_ai_gateway.orchestrator import Orchestrator
from defensive_ai_gateway.policy import PolicyEngine
from defensive_ai_gateway.sample_alerts import available_features, generate_alert, generate_alerts
from defensive_ai_gateway.syslog_router import SyslogPortRouter


class PipelineTest(unittest.TestCase):
    def test_mapping_profile_dry_run_normalizes_real_rasp_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            Repository(str(Path(tmp) / "gateway.db"))
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

    def test_dry_run_rejects_the_same_invalid_timestamp_as_production(self):
        profile = {
            "profile_id": "invalid-time-check",
            "name": "Invalid time check",
            "version": "v1",
            "mappings": {
                "alert_id": "$.id",
                "product": {"literal": "waf"},
                "event_type": "$.event_type",
                "severity": {"literal": "high"},
                "timestamp": "$.timestamp",
            },
        }
        log = {"id": "invalid-time-001", "event_type": "sqli", "timestamp": "not-an-iso-time"}
        result = LogAdapter().dry_run(MappingProfile.from_dict(profile), log)

        self.assertFalse(result["ok"])
        self.assertIn("invalid_raw_alert:timestamp must be an ISO-8601 value", result["errors"])

    def test_auto_infer_detects_product_and_decodes_syslog_json_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)
            vendor_log = {
                "metadata": {"id": "syslog-rasp-001"},
                "device": {"type": "runtime_app_protection"},
                "risk": {"level": "high"},
                "time": "2026-07-22T10:00:00Z",
                "rule": {"name": "SQL injection"},
            }
            envelope = {"hostname": "rasp-agent-01", "appname": "rasp", "message": json.dumps(vendor_log)}

            inferred = state.infer_mapping_profile({"log": envelope})
            self.assertTrue(inferred["ok"], inferred)
            self.assertEqual(inferred["product_detection"]["product"], "rasp")
            self.assertEqual(inferred["product_detection"]["mode"], "auto")
            self.assertTrue(inferred["input"]["syslog_envelope_detected"])

            dry_run = state.dry_run_mapping_profile({"profile": inferred["profile"], "log": envelope})
            self.assertTrue(dry_run["ok"], dry_run["errors"])
            self.assertEqual(dry_run["raw_alert_preview"]["payload"]["syslog_envelope"]["hostname"], "rasp-agent-01")

    def test_seed_does_not_overwrite_a_saved_auto_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)
            profile = state.get_mapping_profile("auto-waf-json").to_dict()
            profile["name"] = "User-maintained WAF mapping"
            state.save_mapping_profile(profile)

            state._seed_mapping_profiles()
            self.assertEqual(state.get_mapping_profile("auto-waf-json").name, "User-maintained WAF mapping")

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

    def test_auto_infer_mapping_profile_for_security_device_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)

            for product in ["waf", "hips", "ndr", "siem"]:
                with self.subTest(product=product):
                    raw_log = state.sample_log(product)
                    inferred = state.infer_mapping_profile(
                        {"log": raw_log, "product": product, "profile_id": f"auto-{product}-json"}
                    )

                    self.assertTrue(inferred["ok"], inferred)
                    self.assertEqual(inferred["profile"]["profile_id"], f"auto-{product}-json")
                    result = state.dry_run_mapping_profile({"profile": inferred["profile"], "log": raw_log})
                    self.assertTrue(result["ok"], result["errors"])
                    self.assertEqual(result["raw_alert_preview"]["product"], product)

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
                trusted_sample=True,
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

    def test_replayed_alert_reuses_immutable_event_and_result(self):
        """Delivery retries must not repeat LLM analysis or create extra links."""
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
                trusted_sample=True,
            )

            first = orchestrator.handle_alert(alert)
            replay = orchestrator.handle_alert(alert)

            self.assertEqual(replay.to_dict(), first.to_dict())
            self.assertEqual(repo.conn.execute("SELECT COUNT(*) FROM raw_alerts").fetchone()[0], 1)
            self.assertEqual(repo.conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0], 1)
            self.assertEqual(repo.conn.execute("SELECT COUNT(*) FROM case_alert_links").fetchone()[0], 1)
            self.assertEqual(repo.conn.execute("SELECT COUNT(*) FROM agent_runs").fetchone()[0], 1)
            event_id = repo.conn.execute("SELECT event_id FROM normalized_events").fetchone()[0]
            self.assertEqual(repo.conn.execute("SELECT event_id FROM agent_runs").fetchone()[0], event_id)

    def test_correlated_alert_updates_existing_case_without_replacing_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            orchestrator = Orchestrator(repo, EventNormalizer(policy), MemoryManager(repo), LocalHeuristicLLM(), policy)
            payload = json.loads(Path("samples/waf_alert.json").read_text(encoding="utf-8"))
            first_alert = RawAlert(
                source=payload["source"], product=payload["product"], event_type=payload["event_type"],
                severity=payload["severity"], timestamp=payload["timestamp"], payload=payload["payload"],
                alert_id=payload["alert_id"],
            )
            second_alert = RawAlert(
                source=payload["source"], product=payload["product"], event_type=payload["event_type"],
                severity=payload["severity"], timestamp=payload["timestamp"], payload=payload["payload"],
                alert_id=f"{payload['alert_id']}-retry-correlation",
            )

            first = orchestrator.handle_alert(first_alert)
            created_at = repo.get_case(first.case_id)["created_at_ms"]
            self.assertIsNotNone(repo.update_case_status(first.case_id, "under_review"))
            second = orchestrator.handle_alert(second_alert)

            self.assertEqual(second.case_id, first.case_id)
            detail = repo.get_case(first.case_id)
            self.assertEqual(detail["status"], "under_review")
            self.assertEqual(detail["created_at_ms"], created_at)
            self.assertEqual(len(detail["linked_alerts"]), 2)
            self.assertEqual(len(detail["agent_runs"]), 2)

    def test_case_list_keeps_creation_order_and_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))

            def result(case_id: str, severity: str, created_at_ms: int) -> AgentResult:
                return AgentResult(
                    case_id=case_id,
                    agent="test-agent",
                    classification="suspicious",
                    confidence=0.8,
                    severity=severity,
                    summary=f"{case_id} summary",
                    evidence=[],
                    missing_evidence=[],
                    recommended_actions=[RecommendedAction(action="review", mode="observe", rationale="test")],
                    dashboard_cards=[],
                    created_at_ms=created_at_ms,
                )

            base = 1_700_000_000_000
            repo.upsert_case(result("case_a", "high", base), "waf")
            repo.upsert_case(result("case_b", "critical", base + 1000), "rasp")
            repo.upsert_case(result("case_c", "low", base + 2000), "waf")

            self.assertEqual([item["case_id"] for item in repo.list_cases()], ["case_c", "case_b", "case_a"])
            repo.update_case_status("case_a", "confirmed_attack")
            self.assertEqual([item["case_id"] for item in repo.list_cases()], ["case_c", "case_b", "case_a"])

            self.assertEqual([item["case_id"] for item in repo.list_cases(product="waf")], ["case_c", "case_a"])
            self.assertEqual([item["case_id"] for item in repo.list_cases(severity="critical")], ["case_b"])
            self.assertEqual([item["case_id"] for item in repo.list_cases(status="confirmed_attack")], ["case_a"])
            self.assertEqual(
                [item["case_id"] for item in repo.list_cases(active_only=True)],
                ["case_c", "case_b", "case_a"],
            )
            self.assertEqual(
                [item["case_id"] for item in repo.list_cases(created_from_ms=base + 500, created_to_ms=base + 1500)],
                ["case_b"],
            )

    def test_active_case_list_filters_terminal_cases_before_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))

            def result(case_id: str, created_at_ms: int) -> AgentResult:
                return AgentResult(
                    case_id=case_id,
                    agent="test-agent",
                    classification="suspicious",
                    confidence=0.8,
                    severity="high",
                    summary=f"{case_id} summary",
                    evidence=[],
                    missing_evidence=[],
                    recommended_actions=[RecommendedAction(action="review", mode="observe", rationale="test")],
                    dashboard_cards=[],
                    created_at_ms=created_at_ms,
                )

            base = 1_700_000_000_000
            repo.upsert_case(result("case_active", base), "waf")
            for index in range(3):
                case_id = f"case_closed_{index}"
                repo.upsert_case(result(case_id, base + index + 1), "waf")
                repo.update_case_status(case_id, "closed")

            # A mixed list limited to three omits the older active Case, which
            # was the source of the misleading empty active queue.
            self.assertNotIn("case_active", [item["case_id"] for item in repo.list_cases(limit=3)])
            self.assertEqual(
                [item["case_id"] for item in repo.list_cases(limit=3, active_only=True)],
                ["case_active"],
            )

    def test_llm_config_update_hides_key_and_rebuilds_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.llm.allowed_hosts = ["llm-gateway.internal"]
            state = GatewayState(config)
            resolution = [(None, None, None, None, ("10.42.0.17", 443))]
            with patch("defensive_ai_gateway.app.socket.getaddrinfo", return_value=resolution):
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

    def test_case_disposition_updates_status_and_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            state = GatewayState(config)
            payload = generate_alert(product="waf", scenario="attack", seed=7)
            result = state.orchestrator.handle_alert(state.alert_from_payload(payload))
            case_id = result.case_id

            updated = state.update_case_disposition(
                case_id,
                {
                    "status": "confirmed_attack",
                    "actor": "analyst-lee",
                    "reason": "verified exploit evidence",
                },
            )

            self.assertTrue(updated["ok"])
            self.assertEqual(updated["case"]["status"], "confirmed_attack")
            self.assertEqual(state.repo.get_case(case_id)["status"], "confirmed_attack")
            self.assertEqual(state.repo.stats()["cases"], 0)
            self.assertEqual(state.repo.stats()["unresolved_cases"], 1)
            audit = state.repo.conn.execute(
                "SELECT actor, action, detail_json FROM audit_log WHERE trace_id = ? ORDER BY created_at_ms DESC LIMIT 1",
                (case_id,),
            ).fetchone()
            self.assertEqual(audit["actor"], "analyst-lee")
            self.assertEqual(audit["action"], "confirm_case_attack")
            self.assertEqual(json.loads(audit["detail_json"])["status"], "confirmed_attack")

            with self.assertRaisesRegex(ValueError, "unsupported case disposition"):
                state.update_case_disposition(case_id, {"status": "block_host"})

            state.update_case_disposition(case_id, {"status": "closed", "actor": "analyst-lee"})
            stats = state.repo.stats()
            self.assertEqual(stats["cases"], 0)
            self.assertEqual(stats["total_cases"], 1)

            state.orchestrator.handle_alert(state.alert_from_payload(payload))
            self.assertEqual(state.repo.get_case(case_id)["status"], "closed")
            self.assertEqual(state.repo.stats()["cases"], 0)

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

    def test_feature_selector_generates_fixed_product_feature(self):
        ndr_sql = generate_alert(product="ndr", scenario="attack", feature="sqli", seed=11)
        ndr_brute = generate_alert(product="ndr", scenario="attack", feature="bruteforce", seed=11)
        rasp_cmd = generate_alert(product="rasp", scenario="attack", feature="command_execution", seed=11)

        self.assertEqual(ndr_sql["payload"]["feature"], "sql_injection")
        self.assertEqual(ndr_sql["event_type"], "sql_injection_detected")
        self.assertEqual(ndr_brute["payload"]["feature"], "brute_force")
        self.assertEqual(ndr_brute["event_type"], "brute_force_detected")
        self.assertEqual(rasp_cmd["payload"]["feature"], "command_execution")
        self.assertEqual(rasp_cmd["payload"]["items"][0]["attack_type"], "command_execution")

    def test_random_feature_generation_is_repeatable_and_covers_ndr_features(self):
        first = generate_alerts(20, product="ndr", scenario="attack", seed=2026)
        second = generate_alerts(20, product="ndr", scenario="attack", seed=2026)

        self.assertEqual(first, second)
        self.assertTrue({item["payload"]["feature"] for item in first}.issubset(set(available_features("ndr"))))
        self.assertGreaterEqual(len({item["payload"]["feature"] for item in first}), 2)

    def test_feature_and_random_scenario_select_a_compatible_scenario(self):
        payload = generate_alert(product="waf", feature="path-traversal", seed=3)
        self.assertEqual(payload["payload"]["feature"], "path_traversal")
        self.assertEqual(payload["payload"]["rule_id"], "WAF-930-LFI")

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

    def test_truncated_memory_context_keeps_dict_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.policy.max_context_bytes = 600
            repo = Repository(config.database.path)
            policy = PolicyEngine(config.policy)
            memory = MemoryManager(repo, policy)
            orchestrator = Orchestrator(repo, EventNormalizer(policy), memory, LocalHeuristicLLM(), policy)
            repo.save_memory(
                {
                    "memory_id": "mem_rasp_fp_large",
                    "layer": "product_long_term",
                    "namespace": memory.product_namespace("rasp"),
                    "retrieval_key": "cloudrasp_jndi_108",
                    "content": "false_positive approved " + ("large-context " * 400),
                    "source_case_id": "case_prior_rasp_fp",
                    "scope": "rasp:false_positive_pattern",
                    "trust_level": "medium",
                    "status": "active",
                    "sensitivity_ok": True,
                    "approved_by": "analyst-lee",
                    "expires_at_ms": None,
                }
            )
            payload = json.loads(Path("samples/rasp_alert.json").read_text(encoding="utf-8"))

            result = orchestrator.handle_alert(GatewayState(config).alert_from_payload(payload))

            self.assertEqual(result.agent, "rasp-agent")
            self.assertIn(result.classification, {"malicious", "suspicious", "insufficient_evidence", "benign"})


class ModelReconciliationTest(unittest.TestCase):
    """Model-backed LLMs (ollama/gateway) must produce logically consistent
    results even when the small local model returns a verdict contradicted by
    all-``info`` dimensions or misclassifies a sample."""

    class _FakeModelLLM(LLMClient):
        is_deterministic = False

        def __init__(self, result: dict):
            self._result = result

        def analyze(self, prompt, context):
            return dict(self._result) if isinstance(self._result, dict) else self._result

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
            trusted_sample=True,
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

    def test_lab_target_requires_review_without_authorization_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state_with_llm(tmp, self._FakeModelLLM(self._weak_malicious_result()))
            payload = json.loads(Path("samples/rasp_alert.json").read_text(encoding="utf-8"))
            result = state.orchestrator.handle_alert(state.alert_from_payload(payload))
            # A known lab route proves neither authorization nor an unapproved
            # attack. Dangerous evidence remains actionable, but must be reviewed.
            self.assertEqual(result.classification, "suspicious")
            dims = result.explanation.get("dimensions", [])
            self.assertGreaterEqual(len(dims), 1)
            self.assertTrue(any(d["status"] in {"risk", "blocked"} for d in dims),
                            f"expected a risk/blocked dimension, got {dims}")
            self.assertFalse(all(d["status"] == "info" for d in dims))

    def test_lab_target_calibration_overrides_consistent_malicious_model_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            consistent = self._weak_malicious_result()
            consistent["analysis_dimensions"] = [
                {"title": "请求特征", "status": "risk", "evidence": "JNDI lookup to ldap sink"},
                {"title": "处置动作", "status": "blocked", "evidence": "RASP blocked"},
            ]
            state = self._state_with_llm(tmp, self._FakeModelLLM(consistent))
            payload = json.loads(Path("samples/rasp_alert.json").read_text(encoding="utf-8"))
            result = state.orchestrator.handle_alert(state.alert_from_payload(payload))
            self.assertEqual(result.classification, "suspicious")
            self.assertIn("【需人工复核】", result.explanation["verdict"])
            titles = {d["title"] for d in result.explanation["dimensions"]}
            self.assertIn("请求特征", titles)

    def test_non_object_model_result_degrades_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state_with_llm(tmp, self._FakeModelLLM(["not", "an", "object"]))
            payload = json.loads(Path("samples/rasp_alert.json").read_text(encoding="utf-8"))
            result = state.orchestrator.handle_alert(state.alert_from_payload(payload))
            self.assertEqual(result.classification, "insufficient_evidence")
            self.assertTrue(result.explanation.get("dimensions"))

    def test_ollama_array_json_degrades_to_dict(self):
        parsed = _parse_json_object('[{"classification":"benign"}]')
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed["classification"], "insufficient_evidence")


class AlertProductRoutingTest(unittest.TestCase):
    """Vendor logs use fingerprints; legacy standard alerts retain the SIEM fallback."""

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
            self.assertEqual(alert.payload["adapter"]["profile_id"], "auto-rasp-json")

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

    def test_syslog_port_router_keeps_security_systems_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            router = SyslogPortRouter(state.config.syslog.product_ports, state.config.syslog.gateway_profiles)
            root = Path(__file__).parent.parent

            for product, port in sorted(state.config.syslog.product_ports.items(), key=lambda item: item[1]):
                with self.subTest(product=product, port=port):
                    raw = (root / "samples_syslog" / product / f"{product}_alert.json").read_bytes()
                    routed = router.route(port, raw, hostname=f"{product}-device-01", appname=product)
                    alert = state.alert_from_payload(routed.payload, routed.profile_id)

                    self.assertEqual(routed.product, product)
                    self.assertEqual(alert.product, product)
                    self.assertNotEqual(alert.product, "siem" if product != "siem" else "waf")
                    self.assertEqual(routed.profile_id, f"auto-{product}-json")
                    self.assertEqual(alert.payload["adapter"]["profile_id"], f"auto-{product}-json")

    def test_syslog_port_route_wins_over_conflicting_content_product(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            router = SyslogPortRouter(state.config.syslog.product_ports, state.config.syslog.gateway_profiles)
            waf_port = state.config.syslog.product_ports["waf"]

            routed = router.route(
                waf_port,
                {
                    "alert": {"id": "conflicting-product-001"},
                    "device": {"type": "hips", "vendor": "mis-tagged-device"},
                    "event": {"type": "should still route as waf"},
                    "risk": {"level": "high"},
                },
                hostname="waf-device-01",
                appname="waf",
            )
            alert = state.alert_from_payload(routed.payload, routed.profile_id)

            self.assertEqual(routed.product, "waf")
            self.assertEqual(alert.product, "waf")
            self.assertIn("declared_product_mismatch:hips", routed.warnings)

    def test_runtime_syslog_config_activates_saved_tcp_or_udp_listener(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            # Avoid binding the default listener set during construction. The
            # fake below models the lifecycle contract without weakening the
            # production check that a listener must actually be alive.
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            config.syslog.embedded_listeners_enabled = True
            tcp_port = 25140
            udp_port = 25141

            class FakeListener:
                def __init__(self, spec):
                    self.spec = spec
                    self.active = False

                def start(self):
                    self.active = True

                def stop(self):
                    self.active = False

                def is_alive(self):
                    return self.active

            try:
                with patch.object(
                    state.syslog_receiver,
                    "_new_listener",
                    side_effect=FakeListener,
                ):
                    tcp_payload = state.update_syslog_config({"product": "waf", "port": tcp_port, "protocol": "tcp"})
                    waf_config = next(item for item in tcp_payload["configs"] if item["product"] == "waf")
                    self.assertEqual(waf_config["protocol"], "tcp")
                    self.assertTrue(waf_config["saved"])

                    udp_payload = state.update_syslog_config({"product": "hips", "port": udp_port, "protocol": "udp"})
                    hips_config = next(item for item in udp_payload["configs"] if item["product"] == "hips")
                    self.assertEqual(hips_config["protocol"], "udp")
                    self.assertTrue(hips_config["saved"])

                    with self.assertRaisesRegex(ValueError, "RASP Syslog requires TCP"):
                        state.update_syslog_config({"product": "rasp", "port": 25143, "protocol": "udp"})

                listeners = state.syslog_config_payload()["listeners"]
                self.assertIn({"product": "waf", "port": tcp_port, "protocol": "tcp", "active": True}, listeners)
                self.assertIn({"product": "hips", "port": udp_port, "protocol": "udp", "active": True}, listeners)
            finally:
                state.stop()

    def test_embedded_rasp_listener_forces_tcp_when_a_legacy_config_says_udp(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            config.syslog.embedded_listeners_enabled = False
            config.syslog.product_ports["rasp"] = 25143
            config.syslog.product_protocols["rasp"] = "udp"
            state = GatewayState(config)
            try:
                config.syslog.embedded_listeners_enabled = True
                with patch.object(state.syslog_receiver, "update") as update:
                    state._activate_configured_syslog_listeners()

                specs = update.call_args.args[0]
                rasp_spec = next(spec for spec in specs if spec.product == "rasp")
                self.assertEqual(rasp_spec.protocol, "tcp")
            finally:
                state.stop()

    def test_external_syslog_deployment_config_is_audited_and_persists_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            config.auth.ingest_token = "collector-secret-must-not-be-returned"
            state = GatewayState(config)
            try:
                payload = state.update_syslog_deployment_config(
                    {
                        "collector_address": "10.20.30.40",
                        "source_cidrs": "10.20.10.15/32, 10.20.11.2/24",
                        "_actor": "config-admin",
                    }
                )
                self.assertEqual(payload["collector_address"], "10.20.30.40")
                self.assertEqual(payload["source_cidrs"], ["10.20.10.15/32", "10.20.11.0/24"])
                self.assertTrue(payload["sync_required"])
                self.assertFalse(payload["ingest_auth"]["exposed"])
                self.assertNotIn(config.auth.ingest_token, json.dumps(payload))
                self.assertEqual(payload["targets"][0], {"product": "waf", "label": "WAF", "port": 15140, "protocol": "tcp"})
                with self.assertRaisesRegex(ValueError, "entire internet"):
                    state.update_syslog_deployment_config(
                        {"collector_address": "10.20.30.40", "source_cidrs": "0.0.0.0/0"}
                    )
            finally:
                state.stop()

            restored = GatewayState(config)
            try:
                restored_payload = restored.syslog_deployment_payload()
                self.assertEqual(restored_payload["collector_address"], "10.20.30.40")
                self.assertEqual(restored_payload["source_cidrs"], ["10.20.10.15/32", "10.20.11.0/24"])
            finally:
                restored.stop()


if __name__ == "__main__":
    unittest.main()
