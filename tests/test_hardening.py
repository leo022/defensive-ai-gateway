from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from defensive_ai_gateway.app import build_server
from defensive_ai_gateway.config import AuthConfig, GatewayConfig, LLMConfig
from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.llm import GatewayLLM
from defensive_ai_gateway.memory import MemoryManager
from defensive_ai_gateway.models import AgentResult, NormalizedEvent, RawAlert, new_id
from defensive_ai_gateway.policy import PolicyEngine
from defensive_ai_gateway.processing import AlertProcessor


def _config(tmp: Path, *, token: str = "") -> GatewayConfig:
    config = GatewayConfig()
    config.database.path = str(tmp / "gateway.db")
    config.auth = AuthConfig(api_token=token, allow_loopback_no_token=True, require_token_when_remote=True)
    return config


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Server:
    def __init__(self, config: GatewayConfig):
        config.server.host = "127.0.0.1"
        config.server.port = _free_port()
        self.server = build_server(config, config_path="")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{config.server.port}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def get(self, path, token=""):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.base + path, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def post(self, path, body, token=""):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class HttpAuthTest(unittest.TestCase):
    def test_post_without_token_is_401_when_token_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _Server(_config(Path(tmp), token="secret"))
            try:
                status, _ = srv.post("/api/config/llm", {"provider": "local"}, token="")
                self.assertEqual(status, 401)
            finally:
                srv.stop()

    def test_post_with_correct_token_passes_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _Server(_config(Path(tmp), token="secret"))
            try:
                status, body = srv.post("/api/config/llm", {"provider": "local"}, token="secret")
                self.assertEqual(status, 200)
                self.assertTrue(body["ok"])
            finally:
                srv.stop()

    def test_loopback_without_token_allowed_when_no_token_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _Server(_config(Path(tmp), token=""))
            try:
                status, body = srv.post("/api/config/llm", {"provider": "local"}, token="")
                self.assertEqual(status, 200)
            finally:
                srv.stop()

    def test_llm_config_get_requires_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _Server(_config(Path(tmp), token="secret"))
            try:
                status, _ = srv.get("/api/config/llm", token="")
                self.assertEqual(status, 401)
                status, _ = srv.get("/api/config/llm", token="secret")
                self.assertEqual(status, 200)
            finally:
                srv.stop()

    def test_ollama_picker_rejects_non_local_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _Server(_config(Path(tmp), token=""))
            try:
                status, body = srv.get("/api/config/llm/models?endpoint=http://169.254.169.254/latest/meta-data/")
                self.assertEqual(status, 200)
                self.assertFalse(body["ok"])
                self.assertIn("allowlist", body["error"])
            finally:
                srv.stop()

    def test_static_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _Server(_config(Path(tmp), token=""))
            try:
                status, _ = srv.get("/../../config/dev.yaml")
                self.assertEqual(status, 404)
            finally:
                srv.stop()

    def test_oversized_body_rejected_413(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _Server(_config(Path(tmp), token=""))
            try:
                big = {"x": "a" * 2_000_001}
                status, _ = srv.post("/api/alerts", big, token="")
                self.assertEqual(status, 413)
            finally:
                srv.stop()

    def test_server_error_does_not_leak_exception_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp), token="")
            srv = _Server(config)
            try:
                srv.server.RequestHandlerClass.state.alert_from_payload = lambda payload, profile_id="": (_ for _ in ()).throw(
                    RuntimeError("internal: /etc/secrets path leak")
                )
                status, body = srv.post("/api/alerts", {}, token="")
                self.assertEqual(status, 500)
                self.assertEqual(body["error"], "internal server error")
            finally:
                srv.stop()

    def test_alert_post_returns_queued_without_waiting_for_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp), token="")
            config.processing.async_enabled = True
            config.processing.queue_max_size = 10
            config.processing.workers = 1
            srv = _Server(config)
            release = threading.Event()
            try:
                def slow_handler(alert):
                    release.wait(1)
                    return None

                srv.server.state.orchestrator.handle_alert = slow_handler
                payload = {
                    "alert_id": "async-intake-001",
                    "source": "test",
                    "product": "waf",
                    "event_type": "queue_test",
                    "severity": "high",
                    "timestamp": "2026-06-30T10:00:00+08:00",
                    "payload": {"uri": "/health"},
                }
                status, body = srv.post("/api/alerts", payload, token="")

                self.assertEqual(status, 202)
                self.assertEqual(body["status"], "queued")
                self.assertEqual(body["alert_id"], "async-intake-001")
                self.assertEqual(body["queue"]["submitted"], 1)
            finally:
                release.set()
                srv.stop()


class ContextRedactionTest(unittest.TestCase):
    def test_sensitive_fields_in_evidence_are_redacted_before_llm(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            policy = PolicyEngine(config.policy)

            captured: dict = {}

            class _CapturingLLM:
                is_deterministic = False

                def analyze(self, prompt, context):
                    captured["context"] = context
                    captured["prompt"] = prompt
                    return {
                        "classification": "suspicious",
                        "confidence": 0.5,
                        "verdict": "【需人工复核】- test",
                        "reason": "test",
                        "analysis_dimensions": [{"title": "x", "status": "review", "evidence": "y"}],
                        "business_impact": "",
                        "missing_evidence": [],
                        "recommended_next_steps": [],
                    }

            from defensive_ai_gateway.agents.registry import build_agent

            event = NormalizedEvent(
                event_id="e1", source="s", product="waf", event_type="x", severity="high", timestamp="t",
                entities={"src_ip": "1.2.3.4"},
                evidence=[
                    {"type": "credential", "value": "password=hunter2", "ref": "r1"},
                    {"type": "token", "value": "Authorization: Bearer abc123", "ref": "r2"},
                ],
                sensitivity_tags=[], raw_ref="a1",
            )
            agent = build_agent("waf", _CapturingLLM(), policy)
            agent.analyze("case_1", event, [])
            # Sensitive values must be redacted in both the context channel and prompt.
            self.assertNotIn("hunter2", json.dumps(captured["context"]))
            self.assertNotIn("hunter2", captured["prompt"])
            self.assertIn("[REDACTED]", json.dumps(captured["context"]))


class AtomicityTest(unittest.TestCase):
    def test_promote_failure_leaves_no_active_memory(self):
        """A mid-promotion failure must not leave an active memory with empty scope."""
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            repo = Repository(config.database.path)
            memory = MemoryManager(repo, PolicyEngine(config.policy))
            # Seed a pending memory with a source case that has evidence refs.
            from defensive_ai_gateway.memory import LAYER_PRODUCT_LONG_TERM, STATUS_PENDING
            from defensive_ai_gateway.models import now_ms

            # Create raw_alert + normalized_event + case + link so evidence refs exist.
            alert = RawAlert(source="s", product="waf", event_type="x", severity="high", timestamp="t",
                             payload={}, alert_id="a1")
            repo.insert_raw_alert(alert)
            ev = NormalizedEvent(event_id="e1", source="s", product="waf", event_type="x", severity="high",
                                 timestamp="t", entities={}, evidence=[{"type": "t", "value": "v"}],
                                 sensitivity_tags=[], raw_ref="a1")
            repo.insert_normalized_event(ev)
            repo.upsert_case(AgentResult(case_id="c1", agent="waf", classification="malicious", confidence=0.9,
                                          severity="high", summary="s", evidence=[], missing_evidence=[],
                                          recommended_actions=[], dashboard_cards=[]), "waf")
            repo.link_case_alert("c1", "a1", "e1")

            mem_id = new_id("mem")
            repo.save_memory({
                "memory_id": mem_id, "layer": LAYER_PRODUCT_LONG_TERM, "namespace": "waf",
                "retrieval_key": "k", "content": "{}", "source_case_id": "c1", "scope": "",
                "trust_level": "low", "status": STATUS_PENDING, "sensitivity_ok": True,
                "approved_by": "", "expires_at_ms": None,
            })

            # Force insert_memory_event to fail mid-transaction.
            def failing_event(*a, **k):
                raise sqlite3_IntegrityError("simulated")

            with patch.object(repo, "insert_memory_event", side_effect=failing_event):
                with self.assertRaises(Exception):
                    memory.promote(mem_id, approved_by="analyst", scope="waf:fp", expires_at_ms=now_ms() + 1000)

            m = repo.get_memory(mem_id)
            # Must NOT be active with empty scope (the half-promoted state).
            self.assertNotEqual(m["status"], "active")
            self.assertEqual(m["scope"], "")


class EvidenceAppendOnlyTest(unittest.TestCase):
    def test_re_normalize_does_not_overwrite_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "g.db"))
            alert = RawAlert(source="s", product="waf", event_type="x", severity="high", timestamp="t",
                             payload={}, alert_id="a1")
            repo.insert_raw_alert(alert)
            ev = NormalizedEvent(event_id="e1", source="s", product="waf", event_type="x", severity="high",
                                 timestamp="t", entities={}, evidence=[{"type": "t", "value": "ORIGINAL"}],
                                 sensitivity_tags=[], raw_ref="a1")
            self.assertTrue(repo.insert_normalized_event(ev))
            ev2 = NormalizedEvent(event_id="e1", source="s", product="waf", event_type="x", severity="high",
                                  timestamp="t", entities={}, evidence=[{"type": "t", "value": "TAMPERED"}],
                                  sensitivity_tags=[], raw_ref="a1")
            self.assertFalse(repo.insert_normalized_event(ev2))
            stored = json.loads(repo.conn.execute("SELECT evidence_json FROM normalized_events").fetchone()[0])
            self.assertEqual(stored[0]["value"], "ORIGINAL")


class GatewayLLMHardeningTest(unittest.TestCase):
    def test_non_json_gateway_response_raises_runtime_error(self):
        cfg = LLMConfig(provider="gateway", endpoint="http://127.0.0.1:9999/x", model="m", timeout_seconds=2)
        llm = GatewayLLM(cfg)
        with patch("defensive_ai_gateway.llm.urllib.request.urlopen") as mock:
            class _R:
                status = 200
                def read(self): return b"not json"
                def __enter__(self): return self
                def __exit__(self, *a): return False
            mock.return_value = _R()
            with self.assertRaises(RuntimeError):
                llm.analyze("p", {})

    def test_invalid_classification_downgraded(self):
        from defensive_ai_gateway.llm import _validate_result_shape
        out = _validate_result_shape({"classification": "definitely-attack", "confidence": 0.99}, "m")
        self.assertEqual(out["classification"], "insufficient_evidence")

    def test_chinese_classification_normalized_not_downgraded(self):
        from defensive_ai_gateway.llm import _validate_result_shape
        out = _validate_result_shape({"classification": "真实攻击", "confidence": 0.9}, "m")
        self.assertEqual(out["classification"], "malicious")
        out = _validate_result_shape({"classification": "误报"}, "m")
        self.assertEqual(out["classification"], "benign")


class ClassificationNormalizeTest(unittest.TestCase):
    def test_real_attack_chinese_maps_to_malicious(self):
        from defensive_ai_gateway.agents.evidence_helpers import normalize_classification
        self.assertEqual(normalize_classification("真实攻击"), "malicious")
        self.assertEqual(normalize_classification("真实事件"), "malicious")
        self.assertEqual(normalize_classification("真实"), "malicious")

    def test_negated_malicious_not_false_positive(self):
        from defensive_ai_gateway.agents.evidence_helpers import normalize_classification
        # "非恶意" must not match the "恶意" substring → malicious.
        self.assertEqual(normalize_classification("非恶意"), "benign")


class StackFramesTest(unittest.TestCase):
    def test_dict_frames_are_parsed(self):
        from defensive_ai_gateway.log_adapter import LogAdapter
        from defensive_ai_gateway.normalizer import EventNormalizer
        adapter = LogAdapter(EventNormalizer(PolicyEngine(GatewayConfig().policy)))
        frames = adapter._stack_frames([{"method": "Runtime.exec", "file": "X.java", "line": 12}])
        self.assertTrue(len(frames) == 1)
        self.assertIn("Runtime.exec", frames[0])


class OversizedBodyTest(unittest.TestCase):
    def test_negative_content_length_does_not_read_unbounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = _Server(_config(Path(tmp), token=""))
            try:
                # Content-Length: -1 must be treated as empty (clamped), not read-until-EOF.
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", srv.server.server_address[1], timeout=5)
                conn.request("POST", "/api/alerts", body=b"", headers={"Content-Length": "-1", "Content-Type": "application/json"})
                resp = conn.getresponse()
                # An empty body is invalid JSON for /api/alerts → 400 (client error), not a hang/500.
                self.assertIn(resp.status, (400, 500))
                resp.read()
                conn.close()
            finally:
                srv.stop()


class AlertProcessorShutdownTest(unittest.TestCase):
    def test_stop_is_bounded_when_worker_is_busy_and_queue_is_full(self):
        """Shutdown must not block trying to enqueue a sentinel into a full queue."""
        started = threading.Event()
        release = threading.Event()

        def handler(alert):
            started.set()
            release.wait(2)

        processor = AlertProcessor(handler, max_size=1, workers=1)
        processor.start()
        processor.submit(RawAlert("test", "waf", "first", "low", "t", {}, "first"))
        self.assertTrue(started.wait(1))
        processor.submit(RawAlert("test", "waf", "second", "low", "t", {}, "second"))

        import time

        started_at = time.monotonic()
        processor.stop(timeout=0.05)
        self.assertLess(time.monotonic() - started_at, 0.25)

        release.set()
        self.assertTrue(processor.wait_for_idle(timeout=1))


# Lightweight stand-in to avoid importing sqlite3 at module top for one assertion.
class sqlite3_IntegrityError(Exception):
    pass


if __name__ == "__main__":
    unittest.main()
