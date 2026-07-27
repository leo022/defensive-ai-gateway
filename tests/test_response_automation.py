from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from defensive_ai_gateway.app import GatewayState, build_server
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.database import SCHEMA_VERSION
from defensive_ai_gateway.models import NormalizedEvent
from defensive_ai_gateway.response_automation import ACTION_BLOCK_IP, compile_response_action


class StructuredResponseActionTest(unittest.TestCase):
    def setUp(self):
        self.event = NormalizedEvent(
            event_id="event-response-1",
            source="rasp",
            product="rasp",
            event_type="command_execution",
            severity="critical",
            timestamp="2026-07-27T00:00:00Z",
            entities={
                "src_ip": "43.154.138.159",
                "host": "106.53.107.29:8080",
                "url": "http://106.53.107.29:8080/bastestground/cmd",
            },
            evidence=[{"ref": "hook-1", "value": "ProcessBuilder"}],
            sensitivity_tags=[],
            raw_ref="alert-response-1",
        )

    def test_explicit_source_ip_block_compiles_from_event_evidence(self):
        action = compile_response_action("临时封禁恶意来源 IP", self.event)
        self.assertEqual(action["action_type"], ACTION_BLOCK_IP)
        self.assertEqual(action["object"], "43.154.138.159/32")
        self.assertEqual(action["scope"]["host"], "106.53.107.29:8080")
        self.assertEqual(action["scope"]["path"], "/bastestground/cmd")
        self.assertEqual(action["event_id"], self.event.event_id)

    def test_non_ip_and_ambiguous_actions_do_not_compile(self):
        self.assertEqual(compile_response_action("切换 RASP 阻断策略", self.event), {})
        self.assertEqual(compile_response_action("持续观察来源 IP", self.event), {})
        self.assertEqual(compile_response_action("临时封禁目标服务", self.event), {})

    def test_invalid_network_object_does_not_compile(self):
        self.event.entities["src_ip"] = "127.0.0.1"
        self.assertEqual(compile_response_action("临时封禁来源 IP", self.event), {})


def _waf_alert(alert_id: str):
    from defensive_ai_gateway.models import RawAlert

    payload = json.loads(Path("samples/waf_alert.json").read_text(encoding="utf-8"))
    payload["alert_id"] = alert_id
    payload["payload"]["src_ip"] = "43.154.138.159"
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


class ApprovalResponseTaskTest(unittest.TestCase):
    def _state(self, directory: str, *, quorum: int = 1) -> GatewayState:
        config = GatewayConfig()
        config.database.path = str(Path(directory) / "gateway.db")
        config.processing.async_enabled = False
        config.policy.approval_quorum = quorum
        return GatewayState(config)

    @staticmethod
    def _executable_approval(state: GatewayState, case_id: str) -> dict:
        approvals = state.repo.get_case(case_id)["approvals"]
        return next(
            item for item in approvals if item["action"].get("execution_action")
        )

    def test_final_quorum_vote_creates_one_durable_shadow_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp, quorum=2)
            try:
                state.response_automation.save_connector(
                    {
                        "name": "Shadow WAF",
                        "endpoint": "https://waf.invalid/response",
                        "execution_mode": "shadow",
                        "enabled": True,
                    },
                    actor="config-admin",
                )
                state.response_automation.save_policy(
                    {
                        "enabled": True,
                        "default_ttl_seconds": 1800,
                        "max_ttl_seconds": 3600,
                        "protected_cidrs": [],
                    },
                    actor="config-admin",
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-shadow-1"))
                approval = ApprovalResponseTaskTest._executable_approval(state, result.case_id)
                self.assertEqual(
                    approval["action"]["execution_action"]["object"],
                    "43.154.138.159/32",
                )
                first = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver-a", "reason": "evidence checked"},
                )
                self.assertEqual(first["approval"]["status"], "pending")
                self.assertIsNone(first["response_task"])
                final = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver-b", "reason": "impact accepted"},
                )
                self.assertEqual(final["approval"]["status"], "approved")
                self.assertEqual(final["response_task"]["status"], "queued")
                task_id = final["response_task"]["task_id"]
                deadline = time.time() + 2
                task = final["response_task"]
                while time.time() < deadline:
                    task = state.repo.get_response_task(task_id)
                    if task["status"] == "shadowed":
                        break
                    time.sleep(0.02)
                self.assertEqual(task["status"], "shadowed")
                self.assertEqual(state.repo.count_response_tasks(), 1)
                refreshed = state.repo.get_approval(approval["approval_id"])
                self.assertEqual(refreshed["response_task"]["task_id"], task_id)
                self.assertEqual(refreshed["execution_status"], "not_executed")
            finally:
                state.stop()

    def test_task_approved_before_configuration_requires_explicit_binding_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                state.response_automation.save_policy(
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-late-config-1"))
                approval = self._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "authorized"},
                )
                task_id = decided["response_task"]["task_id"]
                self.assertEqual(decided["response_task"]["status"], "waiting_configuration")
                self.assertEqual(decided["response_task"]["connector_snapshot"], {})

                connector = state.response_automation.save_connector(
                    {
                        "name": "Late-bound shadow WAF",
                        "endpoint": "https://waf.invalid/response",
                        "execution_mode": "shadow",
                        "enabled": True,
                    },
                    actor="config-admin",
                )
                queued = state.response_automation.dispatch(task_id, actor="responder")
                self.assertEqual(queued["status"], "queued")
                self.assertEqual(queued["connector_id"], connector["connector_id"])
                deadline = time.time() + 2
                task = queued
                while time.time() < deadline:
                    task = state.repo.get_response_task(task_id)
                    if task["status"] == "shadowed":
                        break
                    time.sleep(0.02)
                self.assertEqual(task["status"], "shadowed")
                self.assertEqual(task["connector_version"], connector["version"])
            finally:
                state.stop()

    def test_schema_v15_creates_response_tables_with_kill_switch_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                version = state.repo.conn.execute(
                    "SELECT MAX(version) FROM schema_version"
                ).fetchone()[0]
                self.assertEqual(version, SCHEMA_VERSION)
                tables = {
                    row["name"]
                    for row in state.repo.conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                self.assertTrue(
                    {
                        "response_connectors",
                        "response_policy",
                        "response_tasks",
                        "response_attempts",
                    }.issubset(tables)
                )
                self.assertFalse(state.response_automation.policy()["enabled"])
            finally:
                state.stop()


class _ResponseConnectorHandler(BaseHTTPRequestHandler):
    operations: list[str] = []
    idempotency_keys: list[str] = []
    fail_apply = False

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        operation = str(payload["operation"])
        self.__class__.operations.append(operation)
        self.__class__.idempotency_keys.append(
            str(self.headers.get("X-Idempotency-Key") or "")
        )
        if operation == "apply" and self.__class__.fail_apply:
            body = json.dumps({"ok": False}).encode()
            self.send_response(403)
        else:
            response = {"ok": True, "rule_id": "rule-42"}
            if operation == "verify":
                response["status"] = "active"
            elif operation == "rollback":
                response["status"] = "removed"
            elif operation == "health_check":
                response["status"] = "healthy"
            body = json.dumps(response).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        return


class RealConnectorLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ResponseConnectorHandler)
        _ResponseConnectorHandler.operations = []
        _ResponseConnectorHandler.idempotency_keys = []
        _ResponseConnectorHandler.fail_apply = False
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @staticmethod
    def _wait_for(state: GatewayState, task_id: str, status: str, timeout: float = 3):
        deadline = time.time() + timeout
        task = None
        while time.time() < deadline:
            task = state.repo.get_response_task(task_id)
            if task["status"] == status:
                return task
            time.sleep(0.02)
        return task

    def _state(self, directory: str) -> GatewayState:
        config = GatewayConfig()
        config.database.path = str(Path(directory) / "gateway.db")
        config.processing.async_enabled = False
        config.auth.demo_mode = True
        return GatewayState(config)

    def test_auto_apply_verify_and_snapshot_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                connector = state.response_automation.save_connector(
                    {
                        "name": "BAS WAF",
                        "endpoint": f"http://127.0.0.1:{self.server.server_port}/actions",
                        "execution_mode": "auto",
                        "enabled": True,
                        "timeout_seconds": 2,
                    },
                    actor="config-admin",
                )
                state.response_automation.save_policy(
                    {
                        "enabled": True,
                        "default_ttl_seconds": 1800,
                        "max_ttl_seconds": 3600,
                        "protected_cidrs": [],
                    },
                    actor="config-admin",
                )
                tested = state.response_automation.test_connector(
                    connector["connector_id"], actor="config-admin"
                )
                self.assertEqual(tested["health_status"], "healthy")
                result = state.orchestrator.handle_alert(_waf_alert("response-real-1"))
                approval = ApprovalResponseTaskTest._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "BAS authorized"},
                )
                task_id = decided["response_task"]["task_id"]
                task = self._wait_for(state, task_id, "verified")
                self.assertEqual(task["status"], "verified")
                self.assertEqual(task["remote_rule_id"], "rule-42")
                self.assertGreater(task["expires_at_ms"], task["verified_at_ms"])
                self.assertEqual(
                    _ResponseConnectorHandler.operations[:3],
                    ["health_check", "apply", "verify"],
                )
                operation_keys = _ResponseConnectorHandler.idempotency_keys[:3]
                self.assertTrue(all(operation_keys))
                self.assertEqual(len(set(operation_keys)), 3)

                state.response_automation.save_connector(
                    {
                        "name": "BAS WAF v2",
                        "endpoint": "https://waf.invalid/v2/actions",
                        "execution_mode": "auto",
                        "enabled": True,
                        "timeout_seconds": 2,
                    },
                    actor="config-admin",
                    connector_id=connector["connector_id"],
                )
                state.response_automation.rollback(task_id, actor="responder")
                task = self._wait_for(state, task_id, "rolled_back")
                self.assertEqual(task["status"], "rolled_back")
                self.assertEqual(_ResponseConnectorHandler.operations[-1], "rollback")
                self.assertNotIn(
                    _ResponseConnectorHandler.idempotency_keys[-1], operation_keys
                )
            finally:
                state.stop()

    def test_terminal_case_queues_compensating_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                connector = state.response_automation.save_connector(
                    {
                        "name": "Lifecycle WAF",
                        "endpoint": f"http://127.0.0.1:{self.server.server_port}/actions",
                        "execution_mode": "auto",
                        "enabled": True,
                        "timeout_seconds": 2,
                    },
                    actor="config-admin",
                )
                state.response_automation.save_policy(
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                state.response_automation.test_connector(
                    connector["connector_id"], actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-terminal-1"))
                approval = ApprovalResponseTaskTest._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "authorized"},
                )
                task_id = decided["response_task"]["task_id"]
                self.assertEqual(self._wait_for(state, task_id, "verified")["status"], "verified")

                state.repo.update_case_status(result.case_id, "false_positive")
                state.response_automation.wake()
                task = self._wait_for(state, task_id, "rolled_back")
                self.assertEqual(task["status"], "rolled_back")
                self.assertEqual(_ResponseConnectorHandler.operations[-1], "rollback")
            finally:
                state.stop()

    def test_rollback_failure_can_be_retried_by_responder(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                connector = state.response_automation.save_connector(
                    {
                        "name": "Retryable WAF",
                        "endpoint": f"http://127.0.0.1:{self.server.server_port}/actions",
                        "execution_mode": "auto",
                        "enabled": True,
                    },
                    actor="config-admin",
                )
                state.response_automation.save_policy(
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                state.response_automation.test_connector(
                    connector["connector_id"], actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-rollback-retry-1"))
                approval = ApprovalResponseTaskTest._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "authorized"},
                )
                task_id = decided["response_task"]["task_id"]
                self.assertEqual(self._wait_for(state, task_id, "verified")["status"], "verified")
                state.repo.finish_response_task(
                    task_id, "rollback_failed", error="temporary device outage"
                )

                queued = state.response_automation.rollback(task_id, actor="responder")
                self.assertEqual(queued["status"], "rollback_queued")
                self.assertEqual(
                    self._wait_for(state, task_id, "rolled_back")["status"], "rolled_back"
                )
            finally:
                state.stop()


class ResponseAutomationHTTPRoleTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ResponseConnectorHandler)
        _ResponseConnectorHandler.operations = []
        _ResponseConnectorHandler.idempotency_keys = []
        _ResponseConnectorHandler.fail_apply = False
        self.connector_thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.connector_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.connector_thread.join(timeout=2)

    _wait_for = staticmethod(RealConnectorLifecycleTest._wait_for)

    @staticmethod
    def _state(directory: str) -> GatewayState:
        config = GatewayConfig()
        config.database.path = str(Path(directory) / "gateway.db")
        config.processing.async_enabled = False
        config.auth.demo_mode = True
        return GatewayState(config)

    @staticmethod
    def _request(base: str, path: str, token: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{base}{path}",
            data=data,
            headers={
                "Authorization": f"Bearer {token}",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
            method="POST" if data is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_configuration_approval_and_response_roles_are_separated(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            "os.environ",
            {"DEFENSIVE_AI_RESPONSE_CONNECTOR_TOKEN": "connector-secret-value"},
        ):
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.server.host = "127.0.0.1"
            config.server.port = 0
            config.processing.async_enabled = False
            config.auth.api_token = "admin-token-value"
            config.auth.approver_token = "approver-token-value"
            config.auth.responder_token = "responder-token-value"
            server = build_server(config)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                status, _ = self._request(
                    base,
                    "/api/automation/policy",
                    config.auth.approver_token,
                    {"enabled": True},
                )
                self.assertEqual(status, 403)

                status, payload = self._request(
                    base,
                    "/api/automation/policy",
                    config.auth.api_token,
                    {"enabled": False, "protected_cidrs": ["10.0.0.0/8"]},
                )
                self.assertEqual(status, 200)
                self.assertFalse(payload["policy"]["enabled"])

                connector_body = {
                    "name": "Production WAF",
                    "endpoint": "https://waf.example.internal/actions",
                    "secret_env": "DEFENSIVE_AI_RESPONSE_CONNECTOR_TOKEN",
                    "execution_mode": "manual",
                    "enabled": True,
                }
                status, _ = self._request(
                    base,
                    "/api/automation/connectors",
                    config.auth.responder_token,
                    connector_body,
                )
                self.assertEqual(status, 403)
                status, payload = self._request(
                    base,
                    "/api/automation/connectors",
                    config.auth.api_token,
                    connector_body,
                )
                self.assertEqual(status, 200)
                self.assertTrue(payload["connector"]["credential_configured"])
                self.assertNotIn("connector-secret-value", json.dumps(payload))

                status, payload = self._request(
                    base,
                    "/api/automation/tasks",
                    config.auth.responder_token,
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload["tasks"], [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_http_403_is_terminal_and_not_retried(self):
        _ResponseConnectorHandler.fail_apply = True
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                connector = state.response_automation.save_connector(
                    {
                        "name": "Rejecting WAF",
                        "endpoint": f"http://127.0.0.1:{self.server.server_port}/actions",
                        "execution_mode": "auto",
                        "enabled": True,
                        "timeout_seconds": 2,
                    },
                    actor="config-admin",
                )
                state.response_automation.save_policy(
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                state.response_automation.test_connector(
                    connector["connector_id"], actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-403-1"))
                approval = ApprovalResponseTaskTest._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "authorized"},
                )
                task = self._wait_for(state, decided["response_task"]["task_id"], "failed")
                self.assertEqual(task["status"], "failed")
                self.assertEqual(task["attempts"], 1)
                self.assertIn("HTTP 403", task["last_error"])
                self.assertEqual(_ResponseConnectorHandler.operations.count("apply"), 1)
            finally:
                state.stop()

    def test_protected_source_creates_visible_failed_task_without_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                state.response_automation.save_connector(
                    {
                        "name": "Shadow WAF",
                        "endpoint": "https://waf.invalid/response",
                        "execution_mode": "shadow",
                        "enabled": True,
                    },
                    actor="config-admin",
                )
                state.response_automation.save_policy(
                    {
                        "enabled": True,
                        "default_ttl_seconds": 1800,
                        "max_ttl_seconds": 3600,
                        "protected_cidrs": ["43.154.138.0/24"],
                    },
                    actor="config-admin",
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-protected-1"))
                approval = ApprovalResponseTaskTest._executable_approval(
                    state, result.case_id
                )
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "reviewed"},
                )
                self.assertEqual(decided["approval"]["status"], "approved")
                self.assertEqual(decided["response_task"]["status"], "failed")
                self.assertIn("protected", decided["response_task"]["last_error"])
                self.assertEqual(state.repo.count_response_tasks(), 1)
            finally:
                state.stop()


if __name__ == "__main__":
    unittest.main()
