from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.models import RawAlert, ValidationResult
from scripts.send_demo_alerts import GATE_REVIEW_LABEL, build_demo_payload


class DemoValidationCoverageTest(unittest.TestCase):
    @staticmethod
    def _review_alert() -> RawAlert:
        payload = build_demo_payload("waf", "attack", GATE_REVIEW_LABEL, 4104)
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

    def test_gate_negative_waf_sample_is_review_without_approval(self):
        alert = self._review_alert()

        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            state = GatewayState(config)
            try:
                result = state.orchestrator.handle_alert(alert)
                detail = state.repo.get_case(result.case_id)
                self.assertEqual(alert.payload["rule_id"], "WAF-941-XSS")
                self.assertEqual(result.classification, "malicious")
                self.assertEqual(result.explanation["validation"]["status"], "review")
                self.assertIn(
                    "prompt_injection_detected",
                    [item["code"] for item in result.explanation["validation"]["findings"]],
                )
                finding = next(
                    item
                    for item in result.explanation["validation"]["findings"]
                    if item["code"] == "prompt_injection_detected"
                )
                self.assertIn(f"{alert.alert_id}:rule_info", finding["evidence_refs"])
                rule_info_clue = next(
                    item
                    for item in finding["evidence_clues"]
                    if item["evidence_ref"] == f"{alert.alert_id}:rule_info"
                )
                self.assertIn("ignore previous system instructions", rule_info_clue["excerpt"])
                self.assertTrue(rule_info_clue["field_path"].endswith(".value"))
                self.assertEqual(detail["approvals"], [])
            finally:
                state.stop()

    def test_prompt_injection_review_continues_only_through_audited_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            state = GatewayState(config)
            try:
                result = state.orchestrator.handle_alert(self._review_alert())
                before = state.repo.get_case(result.case_id)
                validation = before["validation_runs"][0]
                self.assertEqual(validation["status"], "review")
                self.assertEqual(before["approvals"], [])
                forged = state.orchestrator.response_advisor.prepare_after_manual_review(
                    validation["event_id"],
                    result,
                    ValidationResult.from_dict(validation),
                    "review_resolution_not_persisted",
                )
                self.assertEqual(len(forged), 1)
                self.assertFalse(state.repo.insert_approval(forged[0].to_dict()))

                routed = state.continue_validation_review(
                    result.case_id,
                    validation["validation_id"],
                    {
                        "actor": "security-analyst",
                        "reason": "核对原始 WAF 规则、请求证据引用和关联告警；未采纳外部载荷文本。",
                    },
                )
                self.assertTrue(routed["created"])
                self.assertEqual(routed["resolution"]["decision"], "continue")
                self.assertEqual(len(routed["approvals"]), 1)

                after = state.repo.get_case(result.case_id)
                self.assertEqual(after["validation_runs"][0]["status"], "review")
                self.assertEqual(
                    after["validation_runs"][0]["manual_review_resolution"]["resolution_id"],
                    routed["resolution"]["resolution_id"],
                )
                self.assertEqual(result.explanation["memory_write_status"], "suppressed_by_validator")
                approval = after["approvals"][0]
                self.assertEqual(approval["validation_id"], validation["validation_id"])
                self.assertEqual(
                    approval["review_resolution_id"], routed["resolution"]["resolution_id"]
                )
                self.assertEqual(approval["execution_status"], "not_executed")

                repeated = state.continue_validation_review(
                    result.case_id,
                    validation["validation_id"],
                    {
                        "actor": "security-analyst",
                        "reason": "重复请求不应创建第二次决议或审批。",
                    },
                )
                self.assertFalse(repeated["created"])
                self.assertEqual(len(state.repo.get_case(result.case_id)["approvals"]), 1)
                audit_count = state.repo.conn.execute(
                    "SELECT COUNT(*) AS count FROM audit_log "
                    "WHERE action = 'manual_validation_review_continued'"
                ).fetchone()["count"]
                self.assertEqual(audit_count, 1)
            finally:
                state.stop()


if __name__ == "__main__":
    unittest.main()
