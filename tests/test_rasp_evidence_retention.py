from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from defensive_ai_gateway.agents.rasp import RaspAgent
from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.llm import LocalHeuristicLLM
from defensive_ai_gateway.log_adapter import LogAdapter, builtin_product_profile, mapping_profile_record
from defensive_ai_gateway.normalizer import EventNormalizer
from defensive_ai_gateway.policy import PolicyEngine
from defensive_ai_gateway.syslog_router import SyslogPortRouter


ROOT = Path(__file__).resolve().parents[1]


class RaspEvidenceRetentionTest(unittest.TestCase):
    def _cloudrasp_log(self) -> dict:
        path = ROOT / "samples_syslog" / "rasp" / "rasp_alert.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def _normalizer(self) -> EventNormalizer:
        return EventNormalizer(PolicyEngine(GatewayConfig().policy))

    def test_cloudrasp_hook_data_is_retained_but_only_a_safe_summary_reaches_evidence(self):
        raw_log = copy.deepcopy(self._cloudrasp_log())
        raw_log["event"]["request_message"]["parameter"] = "{}"
        raw_log["items"][0]["hook_data"] = {"command": "safe-test"}

        adapter = LogAdapter(self._normalizer())
        result = adapter.adapt(builtin_product_profile("rasp"), raw_log)

        self.assertTrue(result["ok"], result["errors"])
        raw_alert = result["raw_alert"]
        self.assertEqual(
            raw_alert.payload["request_parameters"],
            {"state": "empty", "format": "json_object"},
        )
        adapter_types = [item["type"] for item in raw_alert.payload["adapter_evidence"]]
        self.assertIn("hook_data", adapter_types)
        self.assertIn("request_parameters", adapter_types)

        event = self._normalizer().normalize(raw_alert)
        by_type = {item["type"]: item.get("value") for item in event.evidence}
        self.assertEqual(raw_alert.payload["original_log"]["items"][0]["hook_data"], {"command": "safe-test"})
        self.assertEqual(by_type["hook_data"]["state"], "present")
        self.assertEqual(by_type["hook_data"]["semantic_fields"]["command"]["state"], "present")
        self.assertTrue(by_type["hook_data"]["raw_evidence_retained"])
        self.assertNotIn("safe-test", json.dumps(event.evidence, ensure_ascii=False))
        self.assertEqual(by_type["request_parameters"]["state"], "empty")

        result = RaspAgent(LocalHeuristicLLM(), PolicyEngine(GatewayConfig().policy)).analyze(
            "case-rasp-evidence-retention", event, []
        )
        dimensions = {item["title"]: item["evidence"] for item in result.explanation["dimensions"]}
        self.assertIn("请求参数=空 JSON 对象", dimensions["参数特征"])
        self.assertNotIn("缺少 hook_data", dimensions["上下文"])

    def test_full_items_and_request_context_survive_a_long_stacktrace_in_model_context(self):
        raw_log = copy.deepcopy(self._cloudrasp_log())
        raw_log["event"]["request_message"]["parameter"] = '{"url":"jdbc:mysql://probe"}'
        raw_log["event"]["request_message"]["body"] = {"payload": "body-secret-should-not-leave"}
        raw_log["items"][0]["hook_data"] = {"command": "command-secret-should-not-leave"}
        raw_log["items"][0]["stacktrace"] = [
            f"com.example.Frame{index}.invoke(Frame.java:{index})" for index in range(1600)
        ]
        raw_log["items"].append(
            {
                "rule_id": "cloudrasp_cmd_103",
                "rule_name": "恶意命令判断",
                "attack_level": 1,
                "intercept_state": "log",
                "hook_data": {"command": "second-command-secret"},
                "stacktrace": ["java.lang.ProcessBuilder.start(ProcessBuilder.java:1100)"],
            }
        )

        policy = PolicyEngine(GatewayConfig().policy)
        raw_alert = LogAdapter(EventNormalizer(policy)).adapt(
            builtin_product_profile("rasp"), raw_log
        )["raw_alert"]
        event = EventNormalizer(policy).normalize(raw_alert)
        by_type = {item["type"]: item.get("value") for item in event.evidence}

        self.assertEqual(by_type["request_context"]["body"]["state"], "present")
        self.assertTrue(by_type["request_context"]["raw_evidence_retained"])
        self.assertEqual(by_type["rasp_items_context"]["item_count"], 3)
        self.assertEqual(
            {item["rule_id"] for item in by_type["rasp_items_context"]["items"]},
            {"cloudrasp_jndi_108", "cloudrasp_jndi_101", "cloudrasp_cmd_103"},
        )
        self.assertEqual(raw_alert.payload["original_log"]["event"]["request_message"]["body"]["payload"], "body-secret-should-not-leave")

        model_context = policy.sanitize_context(
            {
                "product": "rasp",
                "severity": event.severity,
                "event_type": event.event_type,
                "entities": event.entities,
                "evidence": event.evidence,
                "memory": {},
            }
        )
        model_types = {item["type"] for item in model_context["evidence"]}
        self.assertTrue(
            {
                "request_context",
                "request_parameters",
                "hook_data",
                "rasp_items_context",
                "stack_trace",
                "sink",
            }.issubset(model_types)
        )
        model_text = json.dumps(model_context, ensure_ascii=False)
        self.assertNotIn("body-secret-should-not-leave", model_text)
        self.assertNotIn("command-secret-should-not-leave", model_text)
        self.assertNotIn("second-command-secret", model_text)

    def test_model_missing_claims_are_corrected_when_rasp_proved_the_fields_present(self):
        raw_log = copy.deepcopy(self._cloudrasp_log())
        raw_log["event"]["path"] = "/internal/orders"
        raw_log["event"]["request_message"]["url"] = "http://example.test/internal/orders"
        raw_log["event"]["request_message"]["body"] = {"payload": "not-forwarded"}
        raw_log["items"][0]["hook_data"] = {"command": "not-forwarded"}
        policy = PolicyEngine(GatewayConfig().policy)
        raw_alert = LogAdapter(EventNormalizer(policy)).adapt(
            builtin_product_profile("rasp"), raw_log
        )["raw_alert"]
        event = EventNormalizer(policy).normalize(raw_alert)

        class _MisleadingLlm:
            is_deterministic = False

            def analyze(self, _prompt, _context):
                return {
                    "classification": "suspicious",
                    "confidence": 0.85,
                    "verdict": "【需人工复核】- 缺少完整请求体和具体执行命令内容",
                    "analysis_dimensions": [
                        {"title": "参数特征", "status": "review", "evidence": "缺少完整请求体"},
                        {"title": "上下文", "status": "review", "evidence": "缺少具体执行命令内容"},
                    ],
                    "reason": "缺少完整请求体和具体执行命令内容。",
                    "recommended_next_steps": [],
                    "missing_evidence": ["缺少完整请求体", "缺少具体执行命令内容"],
                    "business_impact": "",
                }

        result = RaspAgent(_MisleadingLlm(), policy).analyze("case-rasp-correction", event, [])
        rendered = json.dumps(result.explanation, ensure_ascii=False)
        self.assertNotIn("缺少完整请求体", rendered)
        self.assertNotIn("缺少具体执行命令内容", rendered)
        self.assertIn("请求上下文已由 RASP 提供", rendered)
        self.assertIn("RASP 已提供关键 hook 字段", rendered)
        self.assertFalse(result.missing_evidence)

    def test_explicit_lab_path_requires_authorization_review_even_for_malicious_model_verdict(self):
        raw_log = copy.deepcopy(self._cloudrasp_log())
        raw_log["event"]["path"] = "/cloudrasp-vulns/cmd/process_builder/postBody"
        raw_log["event"]["request_message"]["url"] = (
            "http://example.test/cloudrasp-vulns/cmd/process_builder/postBody"
        )
        raw_log["event"]["request_message"]["body"] = {"payload": "retained-only"}
        raw_log["items"][0]["hook_data"] = {"command": "retained-only"}
        policy = PolicyEngine(GatewayConfig().policy)
        event = EventNormalizer(policy).normalize(
            LogAdapter(EventNormalizer(policy)).adapt(
                builtin_product_profile("rasp"), raw_log
            )["raw_alert"]
        )

        class _OverconfidentLlm:
            is_deterministic = False

            def analyze(self, _prompt, _context):
                return {
                    "classification": "malicious",
                    "confidence": 0.98,
                    "verdict": "【真实攻击】- 命令执行",
                    "analysis_dimensions": [
                        {"title": "危险调用", "status": "risk", "evidence": "危险 sink 已触达"},
                        {"title": "成功与危害", "status": "risk", "evidence": "命令已执行"},
                    ],
                    "reason": "研判结论：【真实攻击】- 命令执行",
                    "recommended_next_steps": [],
                    "missing_evidence": [],
                    "business_impact": "高风险",
                }

        result = RaspAgent(_OverconfidentLlm(), policy).analyze("case-rasp-lab", event, [])
        self.assertEqual(result.classification, "suspicious")
        self.assertLessEqual(result.confidence, 0.85)
        self.assertIn("【需人工复核】", result.explanation["verdict"])
        self.assertIn("来源身份与授权记录", "\n".join(result.missing_evidence))
        self.assertIn("环境与授权线索", result.explanation["raw_reason"])
        self.assertEqual(result.severity, event.severity)

    def test_high_risk_lab_suspicious_result_is_also_normalized_for_review(self):
        raw_log = copy.deepcopy(self._cloudrasp_log())
        raw_log["event"]["path"] = "/cloudrasp-vulns/cmd/process_builder/postBody"
        raw_log["event"]["request_message"]["url"] = (
            "http://example.test/cloudrasp-vulns/cmd/process_builder/postBody"
        )
        policy = PolicyEngine(GatewayConfig().policy)
        event = EventNormalizer(policy).normalize(
            LogAdapter(EventNormalizer(policy)).adapt(
                builtin_product_profile("rasp"), raw_log
            )["raw_alert"]
        )

        class _OverreachingReviewLlm:
            is_deterministic = False

            def analyze(self, _prompt, _context):
                return {
                    "classification": "suspicious",
                    "confidence": 0.98,
                    "verdict": "【需人工复核】- 已成功执行",
                    "analysis_dimensions": [
                        {"title": "成功与危害", "status": "blocked", "evidence": "命令已执行"},
                    ],
                    "reason": "研判结论：【需人工复核】- 已成功执行",
                    "recommended_next_steps": [],
                    "missing_evidence": [
                        "RASP 原始告警中被脱敏处理的 JDBC 连接 URL 明文",
                        "主机层的网络连接日志",
                    ],
                    "business_impact": "已造成生产影响",
                }

        result = RaspAgent(_OverreachingReviewLlm(), policy).analyze("case-rasp-lab", event, [])
        self.assertEqual(result.classification, "suspicious")
        self.assertLessEqual(result.confidence, 0.85)
        self.assertIn("执行结果审计", result.explanation["verdict"])
        self.assertIn("尚未确认实际执行结果", result.summary)
        missing = "\n".join(result.missing_evidence)
        self.assertIn("原始值已保留，非传输缺失", missing)
        self.assertNotIn("RASP 原始告警中被脱敏处理", missing)
        self.assertIn("主机层的网络连接日志", missing)
        success = next(
            item for item in result.explanation["dimensions"] if item["title"] == "成功与危害"
        )
        self.assertEqual(success["status"], "review")

    def test_test_environment_context_is_dimension_only_not_a_verdict_or_summary_reason(self):
        raw_log = copy.deepcopy(self._cloudrasp_log())
        raw_log["event"].update(
            {
                "app_name": "ai_agent",
                "path": "/bastestground/file/file_input_stream/getParam",
                "web_path": "/srv/ai_agent",
            }
        )
        raw_log["event"]["request_message"]["url"] = (
            "http://106.53.107.29:8080/bastestground/file/file_input_stream/getParam"
        )
        policy = PolicyEngine(GatewayConfig().policy)
        event = EventNormalizer(policy).normalize(
            LogAdapter(EventNormalizer(policy)).adapt(
                builtin_product_profile("rasp"), raw_log
            )["raw_alert"]
        )

        class _LeakyLlm:
            is_deterministic = False

            def __init__(self):
                self.prompt = ""

            def analyze(self, prompt, _context):
                self.prompt = prompt
                return {
                    "classification": "malicious",
                    "confidence": 0.99,
                    "verdict": "【真实攻击】- 靶场路径未见授权工单",
                    "analysis_dimensions": [
                        {"title": "危险调用", "status": "risk", "evidence": "危险 sink 已触达"},
                        {"title": "成功与危害", "status": "risk", "evidence": "命令已执行"},
                    ],
                    "reason": "研判结论：【真实攻击】- 靶场路径未见授权工单",
                    "recommended_next_steps": ["核对靶场测试工单"],
                    "missing_evidence": ["靶场授权工单"],
                    "business_impact": "靶场与生产网络可达",
                }

        llm = _LeakyLlm()
        result = RaspAgent(llm, policy).analyze("case-rasp-test-environment", event, [])

        self.assertEqual(result.classification, "suspicious")
        self.assertNotIn("靶场", result.explanation["verdict"])
        self.assertNotIn("测试环境", result.explanation["verdict"])
        self.assertNotIn("靶场", result.summary)
        self.assertNotIn("测试环境", result.summary)
        self.assertNotIn("靶场", result.explanation["raw_reason"].splitlines()[0])
        self.assertIn("环境与授权线索", result.explanation["raw_reason"])
        dimensions = result.explanation["dimensions"]
        environment = [item for item in dimensions if item["title"] == "环境与授权线索"]
        self.assertEqual(len(environment), 1)
        self.assertIn("疑似靶场线索", environment[0]["evidence"])
        self.assertIn("请求 URL/路径字段命中 `bastestground`", environment[0]["evidence"])
        self.assertIn("调用栈或业务类名命中 `cn.rasp.vuln`", environment[0]["evidence"])
        self.assertNotIn("命中已知测试环境标识", environment[0]["evidence"])
        self.assertNotIn("靶场", "\n".join(result.missing_evidence))
        self.assertTrue(all("靶场" not in action.action for action in result.recommended_actions))
        self.assertIn("环境与授权线索", llm.prompt)
        self.assertIn("不得在 verdict", llm.prompt)

    def test_syslog_and_vendor_integrity_markers_are_retained_without_raw_payload(self):
        raw_log = copy.deepcopy(self._cloudrasp_log())
        wire_message = json.dumps(raw_log, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        routed = SyslogPortRouter(
            {"rasp": 15143}, {"rasp": "auto-rasp-json"}
        ).route(
            15143,
            wire_message,
            hostname="rasp-device-1",
            appname="rasp",
            protocol="tcp",
        )
        raw_alert = LogAdapter(self._normalizer()).adapt(
            builtin_product_profile("rasp"), routed.payload["log"]
        )["raw_alert"]
        integrity = raw_alert.payload["rasp_evidence_integrity"]

        self.assertEqual(integrity["syslog_protocol"], "tcp")
        self.assertEqual(integrity["transport_assurance"], "collector_received_tcp")
        self.assertEqual(integrity["syslog_raw_message_bytes"], len(wire_message))
        self.assertEqual(
            integrity["syslog_raw_message_sha256"],
            routed.envelope["raw_message_sha256"],
        )
        self.assertTrue(integrity["raw_log_sha256"])
        self.assertNotIn(
            raw_log["items"][0]["hook_data"]["url"],
            json.dumps(raw_alert.payload["adapter_evidence"], ensure_ascii=False),
        )

        udp_routed = SyslogPortRouter(
            {"rasp": 15143}, {"rasp": "auto-rasp-json"}
        ).route(
            15143,
            wire_message,
            hostname="rasp-device-1",
            appname="rasp",
            protocol="udp",
        )
        udp_alert = LogAdapter(self._normalizer()).adapt(
            builtin_product_profile("rasp"), udp_routed.payload["log"]
        )["raw_alert"]
        self.assertEqual(
            udp_alert.payload["rasp_evidence_integrity"]["transport_assurance"],
            "legacy_udp_best_effort",
        )

    def test_cloudrasp_blank_parameters_are_explicitly_marked_upstream_empty(self):
        raw_log = copy.deepcopy(self._cloudrasp_log())
        raw_log["event"]["request_message"]["parameter"] = ""
        raw_log["event"]["ID"] = "cloudrasp-upper-id-001"
        raw_log["event"]["request_id"] = ""

        result = LogAdapter(self._normalizer()).adapt(builtin_product_profile("rasp"), raw_log)

        self.assertTrue(result["ok"], result["errors"])
        raw_alert = result["raw_alert"]
        self.assertEqual(raw_alert.alert_id, "cloudrasp-upper-id-001")
        self.assertEqual(raw_alert.payload["request_parameters"], {"state": "empty", "format": "text"})
        event = self._normalizer().normalize(raw_alert)
        by_type = {item["type"]: item.get("value") for item in event.evidence}
        self.assertEqual(by_type["request_parameters"], {"state": "empty", "format": "text"})

    def test_cloudrasp_uppercase_event_id_avoids_collector_mapping_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                payload = {
                    "profile_id": "auto-rasp-json",
                    "log": {
                        "data_type": "attack_event",
                        "event": {
                            "ID": "cloudrasp-upper-id-002",
                            "request_id": "",
                            "app_name": "payment-api",
                            "attack_time": "2026-07-24T10:00:00Z",
                            "request_message": {
                                "method": "",
                                "url": "",
                                "parameter": "",
                                "body": None,
                                "header": None,
                            },
                        },
                        "items": [
                            {
                                "rule_name": "command_execution",
                                "attack_level": 1,
                                "intercept_state": "log",
                                "hook_data": {"command": "safe-test"},
                                "stacktrace": ["java.lang.ProcessBuilder.start"],
                            }
                        ],
                    },
                    "syslog_route": {
                        "route_reason": "port_profile",
                        "product": "rasp",
                        "destination_port": 15143,
                        "collector": "vector",
                    },
                }

                alert = state.alert_from_payload(payload, "auto-rasp-json")

                self.assertEqual(alert.alert_id, "cloudrasp-upper-id-002")
                self.assertNotIn("collector_mapping_fallback", alert.payload)
                self.assertEqual(alert.payload["request_parameters"], {"state": "empty", "format": "text"})
            finally:
                state.stop()

    def test_existing_auto_rasp_profile_is_backfilled_without_replacing_custom_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            first = GatewayState(config)
            try:
                legacy = builtin_product_profile("rasp")
                legacy.profile_id = "auto-rasp-json"
                legacy.version = "v2"
                legacy.mappings["alert_id"] = [
                    item for item in legacy.mappings["alert_id"] if item != "$.event.ID"
                ]
                legacy.mappings.pop("payload.request_parameters", None)
                legacy.evidence_fields = [
                    field
                    for field in legacy.evidence_fields
                    if field.get("type") not in {"hook_data", "request_parameters"}
                ]
                legacy.mappings["payload.custom_context"] = "$.custom_context"
                first.repo.save_mapping_profile(mapping_profile_record(legacy))
            finally:
                first.stop()

            restarted = GatewayState(config)
            try:
                upgraded = restarted.get_mapping_profile("auto-rasp-json")
                self.assertIn("$.event.ID", upgraded.mappings["alert_id"])
                self.assertIn("payload.request_parameters", upgraded.mappings)
                self.assertIn("payload.custom_context", upgraded.mappings)
                evidence_types = {field["type"] for field in upgraded.evidence_fields}
                self.assertTrue({"hook_data", "request_parameters"}.issubset(evidence_types))
            finally:
                restarted.stop()

    def test_analyst_replay_appends_corrected_event_without_copying_raw_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                raw_log = self._cloudrasp_log()
                raw_log["event"]["request_message"]["body"] = {"payload": "retained-only"}
                raw_log["items"][0]["hook_data"] = {"command": "retained-only"}
                alert = state.alert_from_payload(raw_log, "auto-rasp-json")
                first = state.submit_alert(alert)
                case_id = first["case_id"]
                before = state.repo.get_case(case_id)
                source_event_id = before["linked_alerts"][0]["event_id"]

                replay = state.replay_case_alert_analysis(case_id, alert.alert_id, "test-analyst")
                after = state.repo.get_case(case_id)

                self.assertTrue(replay["ok"])
                self.assertTrue(replay["replayed"])
                self.assertEqual(replay["replay"]["source_event_id"], source_event_id)
                self.assertTrue(replay["replay"]["replay_event_id"].startswith(source_event_id))
                self.assertEqual(
                    state.repo.conn.execute("SELECT COUNT(*) FROM raw_alerts").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    state.repo.conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0],
                    2,
                )
                self.assertEqual(len(after["linked_alerts"]), 2)
                self.assertEqual({item["alert_id"] for item in after["linked_alerts"]}, {alert.alert_id})
                self.assertEqual(len(after["agent_runs"]), 2)
                self.assertEqual(after["agent_runs"][0]["prompt_version"], RaspAgent.prompt_version)
                self.assertEqual(after["summary"], replay["analysis"]["summary"])
                self.assertEqual(
                    replay["analysis"]["explanation"]["memory_write_status"],
                    "suppressed_for_analysis_replay",
                )

                reused = state.replay_case_alert_analysis(case_id, alert.alert_id, "test-analyst")
                self.assertFalse(reused["replayed"])
                self.assertEqual(
                    state.repo.conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0],
                    2,
                )
                actions = {
                    row[0]
                    for row in state.repo.conn.execute(
                        "SELECT action FROM audit_log WHERE case_id = ?", (case_id,)
                    ).fetchall()
                }
                self.assertTrue(
                    {
                        "analysis_replay_requested",
                        "analysis_replay_completed",
                        "analysis_replay_reused",
                    }.issubset(actions)
                )
            finally:
                state.stop()


if __name__ == "__main__":
    unittest.main()
