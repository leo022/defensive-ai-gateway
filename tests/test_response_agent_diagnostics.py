from __future__ import annotations

import hashlib
import json
import unittest

from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.log_adapter import LogAdapter, builtin_product_profile


class ResponseAgentDiagnosticIntegrityTests(unittest.TestCase):
    @staticmethod
    def _raw_message(value: dict) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def _envelope(
        cls,
        value: dict,
        *,
        integrity: str = "verified",
    ) -> dict:
        raw_message = cls._raw_message(value)
        envelope = {
            "collector": "syslog-port-router",
            "destination_port": 15140,
            "protocol": "tcp",
            "raw_message": raw_message,
            "raw_message_bytes": len(raw_message.encode("utf-8")),
        }
        if integrity == "verified":
            envelope["raw_message_sha256"] = hashlib.sha256(
                raw_message.encode("utf-8")
            ).hexdigest()
        elif integrity == "mismatch":
            envelope["raw_message_sha256"] = "0" * 64
        return envelope

    @staticmethod
    def _diagnostics(payload: dict) -> tuple[dict, dict[str, dict], list[dict]]:
        descriptor, diagnostics, gaps = Repository._response_agent_capture_layers(
            payload
        )
        return (
            descriptor,
            {item["field"]: item for item in diagnostics},
            gaps,
        )

    def test_correlation_decodes_only_exact_server_owned_envelope_paths(self):
        raw_value = {"trace_id": "trace-server-owned-123"}
        verified = self._envelope(raw_value)
        exact_payloads = (
            {"_syslog_envelope": verified},
            {"syslog_route": verified},
            {"syslog_envelope": verified},
        )
        for payload in exact_payloads:
            with self.subTest(payload=payload):
                values = Repository._response_agent_collect_values(payload)
                self.assertEqual(
                    values["trace_id"],
                    {"trace-server-owned-123"},
                )

        ordinary = {
            "request": {
                "parameters": {
                    "raw_message": self._raw_message(raw_value),
                }
            }
        }
        values = Repository._response_agent_collect_values(ordinary)
        self.assertEqual(values["trace_id"], set())
        for nested_name in (
            "_syslog_envelope",
            "syslog_route",
            "syslog_envelope",
        ):
            with self.subTest(nested_name=nested_name):
                values = Repository._response_agent_collect_values(
                    {"original_log": {nested_name: verified}}
                )
                self.assertEqual(values["trace_id"], set())

    def test_correlation_rejects_hash_mismatched_syslog_pivots(self):
        payload = {
            "_syslog_envelope": self._envelope(
                {"trace_id": "trace-mismatch-must-not-pivot"},
                integrity="mismatch",
            )
        }
        values = Repository._response_agent_collect_values(payload)
        self.assertEqual(values["trace_id"], set())

        unverified = {
            "_syslog_envelope": self._envelope(
                {"trace_id": "trace-unverified-usable"},
                integrity="unverified",
            )
        }
        values = Repository._response_agent_collect_values(unverified)
        self.assertEqual(values["trace_id"], {"trace-unverified-usable"})

    def test_hash_mismatch_403_is_visible_but_not_authoritative(self):
        payload = {
            "method": "GET",
            "uri": "/admin",
            "_syslog_envelope": self._envelope(
                {
                    "http": {
                        "request": {"method": "GET", "uri": "/admin"},
                        "response": {"status_code": 403},
                    }
                },
                integrity="mismatch",
            ),
        }
        descriptor, diagnostics, gaps = self._diagnostics(payload)
        status = diagnostics["http_response_status"]

        self.assertEqual(descriptor["syslog_message_integrity"], "mismatch")
        self.assertEqual(status["syslog_state"], "captured_nonempty")
        self.assertEqual(status["syslog_observed_value"], "403")
        self.assertFalse(status["syslog_usable"])
        self.assertNotEqual(status["provenance"], "syslog_raw_message")
        self.assertEqual(status["state"], "not_observed")
        self.assertNotIn("observed_value", status)
        self.assertEqual(
            status["mapping_consistency"],
            "syslog_integrity_mismatch",
        )
        self.assertTrue(
            any(
                gap["field"] == "http_response_status"
                and gap["reason"] == "syslog_integrity_mismatch"
                for gap in gaps
            )
        )

    def test_real_waf_profile_separates_projection_original_and_syslog(self):
        raw_log = {
            "alert": {
                "id": "waf-diagnostic-layer-001",
                "category": "web_attack",
            },
            "device": {"vendor": "edge-waf", "type": "waf"},
            "risk": {"level": "high"},
            "event": {
                "time": "2026-07-29T10:00:00Z",
                "type": "SQL injection blocked",
            },
            "rule": {"id": "WAF-942", "name": "SQL injection"},
            "http": {
                "client_ip": "203.0.113.20",
                "method": "POST",
                "uri": "/payments/search",
                "status": 403,
            },
            "application": {"name": "payments-api"},
        }
        envelope = self._envelope(raw_log)
        result = LogAdapter().adapt(
            builtin_product_profile("waf"),
            raw_log,
            trusted_syslog_envelope=envelope,
        )
        self.assertTrue(result["ok"], result["errors"])
        payload = result["raw_alert"].payload
        self.assertEqual(payload["http"], raw_log["http"])

        descriptor, diagnostics, gaps = self._diagnostics(payload)
        status = diagnostics["http_response_status"]
        self.assertEqual(descriptor["syslog_message_integrity"], "verified")
        self.assertEqual(status["mapped_state"], "not_observed")
        self.assertEqual(status["original_log_state"], "captured_nonempty")
        self.assertEqual(status["syslog_state"], "captured_nonempty")
        self.assertEqual(
            status["original_log_json_pointer"],
            "/original_log/http/status",
        )
        self.assertEqual(status["syslog_json_pointer"], "/http/status")
        self.assertEqual(status["observed_value"], "403")
        self.assertEqual(status["provenance"], "syslog_raw_message")
        self.assertEqual(status["provenance_confidence"], "verified")
        self.assertTrue(
            any(
                gap["field"] == "http_response_status"
                and gap["reason"] == "field_available_in_raw_evidence_not_mapped"
                for gap in gaps
            )
        )

    def test_unverified_syslog_is_usable_and_labeled(self):
        payload = {
            "_syslog_envelope": self._envelope(
                {
                    "http": {
                        "method": "GET",
                        "uri": "/health",
                        "status": 204,
                    }
                },
                integrity="unverified",
            )
        }
        descriptor, diagnostics, _gaps = self._diagnostics(payload)
        status = diagnostics["http_response_status"]
        self.assertEqual(descriptor["syslog_message_integrity"], "unverified")
        self.assertEqual(status["observed_value"], "204")
        self.assertEqual(status["provenance"], "syslog_raw_message")
        self.assertEqual(status["provenance_confidence"], "unverified")
        self.assertTrue(status["syslog_usable"])

    def test_raw_incomplete_request_is_not_overwritten_by_mapped_empty(self):
        raw_log = {
            "http": {
                "request": {
                    "method": "POST",
                    "uri": "/upload",
                    "headers": {"Content-Length": "100"},
                }
            }
        }
        payload = {
            "method": "POST",
            "uri": "/upload",
            "request_body": "",
            "request_parameters": {},
            "_syslog_envelope": self._envelope(raw_log),
        }
        _descriptor, diagnostics, gaps = self._diagnostics(payload)
        request_payload = diagnostics["http_request_payload"]
        self.assertEqual(request_payload["mapped_state"], "captured_empty")
        self.assertEqual(request_payload["syslog_state"], "captured_incomplete")
        self.assertEqual(request_payload["state"], "captured_incomplete")
        self.assertEqual(
            request_payload["reason"],
            "declared_request_body_missing",
        )
        self.assertEqual(request_payload["provenance"], "syslog_raw_message")
        self.assertTrue(
            any(
                gap["field"] == "http_request_payload"
                and gap["reason"]
                == "raw_capture_conflicts_with_mapped_projection"
                for gap in gaps
            )
        )

    def test_http_status_skips_zero_and_uses_later_valid_candidate(self):
        payload = {
            "event": {"response_message": {"status_code": 0}},
            "http": {"response": {"status_code": 403}},
        }
        diagnostics = {
            item["field"]: item
            for item in Repository._response_agent_capture_diagnostics(payload)
        }
        status = diagnostics["http_response_status"]
        self.assertEqual(status["state"], "captured_nonempty")
        self.assertEqual(status["observed_value"], "403")
        self.assertEqual(status["json_pointer"], "/http/response/status_code")

    def test_top_level_status_fields_require_http_context(self):
        for field in ("status", "status_code", "response_code"):
            with self.subTest(field=field):
                diagnostics = {
                    item["field"]: item
                    for item in Repository._response_agent_capture_diagnostics(
                        {field: 403, "process": {"name": "java"}}
                    )
                }
                self.assertEqual(
                    diagnostics["http_response_status"]["state"],
                    "not_observed",
                )

    def test_ecs_body_byte_metadata_is_not_treated_as_captured_content(self):
        diagnostics = {
            item["field"]: item
            for item in Repository._response_agent_capture_diagnostics(
                {
                    "http": {
                        "request": {
                            "method": "POST",
                            "body": {"bytes": 512},
                        },
                        "response": {"body": {"bytes": 42}},
                    },
                    "url": {"original": "https://example.test/upload"},
                }
            )
        }
        request_body = diagnostics["http_request_body"]
        self.assertEqual(request_body["state"], "captured_incomplete")
        self.assertTrue(request_body["metadata_only"])
        self.assertEqual(request_body["declared_bytes"], 512)
        self.assertEqual(
            diagnostics["http_request_payload"]["state"],
            "captured_incomplete",
        )
        self.assertNotEqual(
            diagnostics["http_request_payload"]["reason"],
            "request_content_present",
        )
        self.assertEqual(
            diagnostics["http_response_body"]["state"],
            "captured_incomplete",
        )

    def test_camel_case_body_metadata_and_status_text_preserve_http_semantics(self):
        diagnostics = {
            item["field"]: item
            for item in Repository._response_agent_capture_diagnostics(
                {
                    "http": {
                        "request": {
                            "method": "POST",
                            "body": {"contentLength": 0},
                        },
                        "response": {"status_code": "403 Forbidden"},
                    },
                    "url": {"original": "https://example.test/upload"},
                }
            )
        }

        request_body = diagnostics["http_request_body"]
        self.assertEqual(request_body["state"], "captured_empty")
        self.assertTrue(request_body["metadata_only"])
        self.assertEqual(request_body["declared_bytes"], 0)
        self.assertEqual(
            diagnostics["http_request_payload"]["state"],
            "captured_empty",
        )
        self.assertEqual(
            diagnostics["http_response_status"]["observed_value"],
            "403",
        )

    def test_generic_request_id_does_not_make_business_status_http(self):
        diagnostics = {
            item["field"]: item
            for item in Repository._response_agent_capture_diagnostics(
                {
                    "request": {"id": "job-1"},
                    "status": 403,
                    "process": {"name": "java"},
                }
            )
        }
        self.assertEqual(
            diagnostics["http_response_status"]["state"],
            "not_observed",
        )

    def test_generic_top_level_method_does_not_make_business_status_http(self):
        diagnostics = {
            item["field"]: item
            for item in Repository._response_agent_capture_diagnostics(
                {
                    "method": "reconcile",
                    "status": 403,
                    "process": {"name": "java"},
                }
            )
        }
        self.assertEqual(
            diagnostics["http_response_status"]["state"],
            "not_observed",
        )


if __name__ == "__main__":
    unittest.main()
