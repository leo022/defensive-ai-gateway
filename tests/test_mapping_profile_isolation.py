from __future__ import annotations

import json
import unittest
from pathlib import Path

from defensive_ai_gateway.log_adapter import LogAdapter, builtin_product_profile


ROOT = Path(__file__).resolve().parents[1]
NON_RASP_PRODUCTS = ("waf", "hips", "ndr", "siem")
RASP_ONLY_MARKERS = (
    "items[0]",
    "stacktrace",
    "stack_trace",
    "hook_data",
    "taint_source",
    "sink",
    "intercept_state",
)


class BuiltinProductProfileIsolationTest(unittest.TestCase):
    def test_non_rasp_profiles_have_correct_source_fallback_and_no_rasp_extractors(self):
        adapter = LogAdapter()
        for product in NON_RASP_PRODUCTS:
            with self.subTest(product=product):
                profile = builtin_product_profile(product)
                source_fallback = profile.mappings["source"][-1]
                self.assertEqual(source_fallback, {"literal": product})

                profile_shape = json.dumps(
                    {"mappings": profile.mappings, "evidence_fields": profile.evidence_fields},
                    ensure_ascii=False,
                ).lower()
                for marker in RASP_ONLY_MARKERS:
                    self.assertNotIn(marker, profile_shape)

                result = adapter.adapt(
                    profile,
                    {
                        "alert_id": f"{product}-fallback-1",
                        "event_type": "test_event",
                        "severity": "high",
                        "timestamp": "2026-07-14T10:00:00+08:00",
                    },
                )
                self.assertTrue(result["ok"], result["errors"])
                self.assertEqual(result["raw_alert"].source, product)
                self.assertEqual(result["raw_alert"].product, product)

    def test_native_samples_keep_product_specific_source_and_evidence(self):
        adapter = LogAdapter()
        expected_evidence = {
            "waf": "payload_category",
            "hips": "command_line",
            "ndr": "sni",
            "siem": "signals",
        }
        for product in NON_RASP_PRODUCTS:
            with self.subTest(product=product):
                sample_path = ROOT / "samples_syslog" / product / f"{product}_alert.json"
                sample = json.loads(sample_path.read_text(encoding="utf-8"))
                result = adapter.adapt(builtin_product_profile(product), sample)
                self.assertTrue(result["ok"], result["errors"])
                self.assertEqual(result["raw_alert"].product, product)
                self.assertEqual(result["raw_alert"].source, sample["device"]["vendor"])
                evidence_types = {item["type"] for item in result["adapter_evidence"]}
                self.assertIn(expected_evidence[product], evidence_types)

    def test_non_rasp_inference_does_not_generate_rasp_fields_or_aliases(self):
        adapter = LogAdapter()
        for product in NON_RASP_PRODUCTS:
            with self.subTest(product=product):
                sample_path = ROOT / "samples_syslog" / product / f"{product}_alert.json"
                sample = json.loads(sample_path.read_text(encoding="utf-8"))
                inferred = adapter.infer_mapping_profile(sample, product=product, profile_id=f"auto-{product}-json")
                profile = inferred["profile"]
                self.assertEqual(profile["mappings"]["source"], {"literal": product})
                self.assertNotIn("rasp", profile["product_map"])
                profile_shape = json.dumps(
                    {"mappings": profile["mappings"], "evidence_fields": profile["evidence_fields"]},
                    ensure_ascii=False,
                ).lower()
                for marker in RASP_ONLY_MARKERS:
                    self.assertNotIn(marker, profile_shape)
                field_targets = {field["target"] for field in inferred["fields"]}
                self.assertTrue(field_targets.isdisjoint({"payload.stack_trace", "payload.sink", "payload.hook_data", "payload.taint_source"}))

    def test_rasp_profile_keeps_runtime_specific_extractors(self):
        profile_shape = json.dumps(builtin_product_profile("rasp").to_dict(), ensure_ascii=False).lower()
        self.assertIn("stacktrace", profile_shape)
        self.assertIn("rasp_sink_from_stacktrace", profile_shape)


if __name__ == "__main__":
    unittest.main()
