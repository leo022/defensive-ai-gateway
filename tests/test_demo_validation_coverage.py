from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.models import RawAlert
from scripts.send_demo_alerts import GATE_REVIEW_LABEL, build_demo_payload


class DemoValidationCoverageTest(unittest.TestCase):
    def test_gate_negative_waf_sample_is_review_without_approval(self):
        payload = build_demo_payload("waf", "attack", GATE_REVIEW_LABEL, 4104)
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
                self.assertEqual(detail["approvals"], [])
            finally:
                state.stop()


if __name__ == "__main__":
    unittest.main()
