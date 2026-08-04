from __future__ import annotations

import json
import sqlite3
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
from defensive_ai_gateway.config import AuthPrincipalConfig, GatewayConfig
from defensive_ai_gateway.database import SCHEMA_VERSION, Repository
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
                self.assertEqual(task["playbook_id"], "playbook_network_block_source")
                self.assertEqual(task["playbook_version"], 1)
                self.assertEqual(task["priority"], "high")
                self.assertGreater(task["sla_due_at_ms"], task["created_at_ms"])
                evaluations = state.response_automation.shadow_evaluations()
                self.assertEqual(len(evaluations), 1)
                self.assertEqual(evaluations[0]["task_id"], task_id)
                self.assertEqual(evaluations[0]["status"], "pending")
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
                        "response_playbooks",
                        "response_shadow_evaluations",
                    }.issubset(tables)
                )
                self.assertFalse(state.response_automation.policy()["enabled"])
                playbooks = state.response_automation.playbooks()
                self.assertEqual(len(playbooks), 1)
                self.assertEqual(playbooks[0]["status"], "active")
            finally:
                state.stop()

    def test_schema_v19_migrates_existing_response_task_to_operations_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "gateway.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.executescript(
                    """
                    CREATE TABLE schema_version (
                      version INTEGER PRIMARY KEY,
                      applied_at_ms INTEGER NOT NULL
                    );
                    INSERT INTO schema_version(version, applied_at_ms) VALUES (19, 1);
                    CREATE TABLE response_tasks (
                      task_id TEXT PRIMARY KEY,
                      approval_id TEXT NOT NULL UNIQUE,
                      case_id TEXT NOT NULL,
                      event_id TEXT NOT NULL,
                      action_type TEXT NOT NULL,
                      action_json TEXT NOT NULL,
                      connector_id TEXT,
                      connector_version INTEGER NOT NULL DEFAULT 0,
                      connector_snapshot_json TEXT NOT NULL DEFAULT '{}',
                      status TEXT NOT NULL,
                      idempotency_key TEXT NOT NULL UNIQUE,
                      attempts INTEGER NOT NULL DEFAULT 0,
                      max_attempts INTEGER NOT NULL DEFAULT 5,
                      available_at_ms INTEGER NOT NULL,
                      claimed_at_ms INTEGER,
                      remote_rule_id TEXT NOT NULL DEFAULT '',
                      last_error TEXT NOT NULL DEFAULT '',
                      verified_at_ms INTEGER,
                      expires_at_ms INTEGER,
                      created_by TEXT NOT NULL,
                      created_at_ms INTEGER NOT NULL,
                      updated_at_ms INTEGER NOT NULL
                    );
                    INSERT INTO response_tasks(
                      task_id, approval_id, case_id, event_id, action_type, action_json,
                      status, idempotency_key, available_at_ms, verified_at_ms,
                      created_by, created_at_ms, updated_at_ms
                    ) VALUES (
                      'task-legacy', 'approval-legacy', 'case-legacy', 'event-legacy',
                      'network.block_ip', '{}', 'verified', 'legacy-key', 1000, 2000,
                      'legacy', 1000, 2100
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()

            repo = Repository(str(db_path))
            try:
                migrated = repo.get_response_task("task-legacy")
                self.assertEqual(migrated["priority"], "medium")
                self.assertEqual(migrated["playbook_id"], "playbook_network_block_source")
                self.assertEqual(migrated["playbook_version"], 1)
                self.assertEqual(migrated["sla_due_at_ms"], 1_801_000)
                self.assertEqual(migrated["sla_completed_at_ms"], 2_000)
                self.assertEqual(migrated["sla_status"], "met")
                self.assertEqual(repo.list_response_playbooks()[0]["status"], "active")
                self.assertEqual(
                    repo.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0],
                    SCHEMA_VERSION,
                )
            finally:
                repo.conn.close()

    def test_playbook_versions_bind_immutably_to_new_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                playbook = state.response_automation.save_playbook(
                    {
                        "playbook_id": "playbook_waf_block_source",
                        "name": "WAF 来源封禁",
                        "description": "WAF 高危来源的受控临时封禁。",
                        "owner": "SOC Response",
                        "trigger_products": ["waf"],
                        "action_type": "network.block_ip",
                        "risk_tier": "critical",
                        "sla_minutes": 15,
                        "publish": True,
                    },
                    actor="config-admin",
                )
                self.assertEqual(playbook["status"], "active")
                state.response_automation.save_policy(
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-playbook-1"))
                approval = self._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "reviewed"},
                )
                task = decided["response_task"]
                self.assertEqual(task["playbook_id"], playbook["playbook_id"])
                self.assertEqual(task["playbook_version"], playbook["version"])
                self.assertEqual(task["priority"], "critical")
                self.assertEqual(task["sla_due_at_ms"] - task["created_at_ms"], 900_000)

                new_version = state.response_automation.save_playbook(
                    {
                        **playbook,
                        "risk_tier": "high",
                        "sla_minutes": 30,
                        "publish": True,
                    },
                    actor="config-admin",
                    playbook_id=playbook["playbook_id"],
                )
                self.assertEqual(new_version["version"], playbook["version"] + 1)
                self.assertEqual(
                    state.repo.get_response_task(task["task_id"])["playbook_version"],
                    playbook["version"],
                )
            finally:
                state.stop()

    def test_playbook_create_rolls_back_when_audit_write_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                with patch.object(
                    state.repo,
                    "insert_audit",
                    side_effect=RuntimeError("audit unavailable"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                        state.response_automation.save_playbook(
                            {
                                "playbook_id": "playbook_atomic_create",
                                "name": "Atomic create",
                                "owner": "SOC Response",
                                "trigger_products": ["waf"],
                                "risk_tier": "high",
                                "sla_minutes": 20,
                            },
                            actor="config-admin",
                        )
                self.assertIsNone(
                    state.repo.get_response_playbook("playbook_atomic_create", 1)
                )
            finally:
                state.stop()

    def test_task_operations_support_assignment_sla_and_external_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                state.response_automation.save_policy(
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-operations-1"))
                approval = self._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "reviewed"},
                )
                task = decided["response_task"]
                updated = state.response_automation.update_task_operations(
                    task["task_id"],
                    {
                        "assignee": "soc-responder-a",
                        "priority": "critical",
                        "sla_due_at_ms": task["created_at_ms"],
                        "acknowledged": True,
                        "handover_note": "交接给白班确认业务影响。",
                        "ticket_ref": "INC-2026-0042",
                        "asset_ref": "CMDB-APP-17",
                        "asset_criticality": "high",
                        "business_owner": "Payments Platform",
                    },
                    actor="soc-responder-a",
                )
                self.assertEqual(updated["assignee"], "soc-responder-a")
                self.assertEqual(updated["priority"], "critical")
                self.assertTrue(updated["acknowledged"])
                self.assertEqual(updated["ticket_ref"], "INC-2026-0042")
                self.assertEqual(updated["asset_ref"], "CMDB-APP-17")
                self.assertEqual(updated["sla_status"], "breached")
                filtered = state.repo.list_response_tasks(
                    priority="critical", assignee="soc-responder-a", sla_status="breached"
                )
                self.assertEqual([item["task_id"] for item in filtered], [task["task_id"]])
                operations = state.repo.response_task_stats()["operations"]
                self.assertEqual(operations["unassigned"], 0)
                self.assertEqual(operations["acknowledged"], 1)
                self.assertEqual(operations["sla_breached"], 1)

                terminal = state.repo.finish_response_task(
                    task["task_id"], "failed", expected_status=task["status"], error="test"
                )
                completed_at = terminal["sla_completed_at_ms"]
                changed = state.response_automation.update_task_operations(
                    task["task_id"],
                    {"handover_note": "终态补充说明不应改变 SLA 结果。"},
                    actor="soc-responder-b",
                )
                self.assertEqual(changed["sla_completed_at_ms"], completed_at)
                self.assertEqual(changed["sla_status"], "breached")
                with self.assertRaisesRegex(ValueError, "SLA deadline cannot be changed"):
                    state.response_automation.update_task_operations(
                        task["task_id"],
                        {"sla_due_at_ms": task["created_at_ms"] + 600_000},
                        actor="soc-responder-b",
                    )
            finally:
                state.stop()

    def test_task_operations_roll_back_when_audit_write_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                state.response_automation.save_policy(
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-operations-atomic-1"))
                approval = self._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "reviewed"},
                )
                task_id = decided["response_task"]["task_id"]
                with patch.object(
                    state.repo,
                    "insert_audit",
                    side_effect=RuntimeError("audit unavailable"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                        state.response_automation.update_task_operations(
                            task_id,
                            {"assignee": "soc-responder-a", "acknowledged": True},
                            actor="soc-responder-a",
                        )
                unchanged = state.repo.get_response_task(task_id)
                self.assertEqual(unchanged["assignee"], "")
                self.assertFalse(unchanged["acknowledged"])
            finally:
                state.stop()

    def test_shadow_evaluation_is_decided_once_with_audited_reason(self):
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
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-shadow-review-1"))
                approval = self._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "reviewed"},
                )
                task_id = decided["response_task"]["task_id"]
                deadline = time.time() + 2
                evaluations = []
                while time.time() < deadline:
                    evaluations = state.response_automation.shadow_evaluations()
                    if evaluations:
                        break
                    time.sleep(0.02)
                self.assertEqual(len(evaluations), 1)
                evaluation = state.response_automation.decide_shadow_evaluation(
                    evaluations[0]["evaluation_id"],
                    {"decision": "accepted", "reason": "证据充分，建议动作与人工判断一致。"},
                    actor="soc-analyst",
                )
                self.assertEqual(evaluation["status"], "accepted")
                self.assertEqual(evaluation["task_id"], task_id)
                with self.assertRaisesRegex(ValueError, "no longer pending"):
                    state.response_automation.decide_shadow_evaluation(
                        evaluations[0]["evaluation_id"],
                        {"decision": "rejected", "reason": "重复提交不应覆盖原决策。"},
                        actor="soc-analyst",
                    )
            finally:
                state.stop()

    def test_shadow_decision_rolls_back_when_audit_write_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                state.response_automation.save_connector(
                    {
                        "name": "Atomic Shadow WAF",
                        "endpoint": "https://waf.invalid/response",
                        "execution_mode": "shadow",
                        "enabled": True,
                    },
                    actor="config-admin",
                )
                state.response_automation.save_policy(
                    {"enabled": True, "protected_cidrs": []}, actor="config-admin"
                )
                result = state.orchestrator.handle_alert(_waf_alert("response-shadow-atomic-1"))
                approval = self._executable_approval(state, result.case_id)
                state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "reviewed"},
                )
                deadline = time.time() + 2
                evaluations = []
                while time.time() < deadline:
                    evaluations = state.response_automation.shadow_evaluations()
                    if evaluations:
                        break
                    time.sleep(0.02)
                self.assertEqual(len(evaluations), 1)
                evaluation_id = evaluations[0]["evaluation_id"]
                with patch.object(
                    state.repo,
                    "insert_audit",
                    side_effect=RuntimeError("audit unavailable"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                        state.response_automation.decide_shadow_evaluation(
                            evaluation_id,
                            {"decision": "accepted", "reason": "证据与人工结论保持一致。"},
                            actor="soc-analyst",
                        )
                pending = state.response_automation.shadow_evaluations(status="pending")
                self.assertEqual([item["evaluation_id"] for item in pending], [evaluation_id])
            finally:
                state.stop()


class _ResponseConnectorHandler(BaseHTTPRequestHandler):
    operations: list[str] = []
    idempotency_keys: list[str] = []
    fail_apply = False
    block_apply_response = False
    apply_received = threading.Event()
    release_apply_response = threading.Event()
    block_verify_response = False
    verify_received = threading.Event()
    release_verify_response = threading.Event()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        operation = str(payload["operation"])
        self.__class__.operations.append(operation)
        self.__class__.idempotency_keys.append(
            str(self.headers.get("X-Idempotency-Key") or "")
        )
        if operation == "apply":
            self.__class__.apply_received.set()
            if self.__class__.block_apply_response:
                self.__class__.release_apply_response.wait(timeout=3)
        if operation == "verify":
            self.__class__.verify_received.set()
            if self.__class__.block_verify_response:
                self.__class__.release_verify_response.wait(timeout=3)
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
        _ResponseConnectorHandler.block_apply_response = False
        _ResponseConnectorHandler.apply_received = threading.Event()
        _ResponseConnectorHandler.release_apply_response = threading.Event()
        _ResponseConnectorHandler.block_verify_response = False
        _ResponseConnectorHandler.verify_received = threading.Event()
        _ResponseConnectorHandler.release_verify_response = threading.Event()
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

    def test_terminal_case_during_remote_apply_rolls_back_without_verifying(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            _ResponseConnectorHandler.block_apply_response = True
            try:
                connector = state.response_automation.save_connector(
                    {
                        "name": "Race WAF",
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
                result = state.orchestrator.handle_alert(_waf_alert("response-race-1"))
                approval = ApprovalResponseTaskTest._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "authorized"},
                )
                task_id = decided["response_task"]["task_id"]
                self.assertTrue(_ResponseConnectorHandler.apply_received.wait(timeout=2))
                self.assertEqual(state.repo.get_response_task(task_id)["status"], "running")

                state.repo.update_case_status(result.case_id, "closed")
                _ResponseConnectorHandler.release_apply_response.set()

                task = self._wait_for(state, task_id, "rolled_back")
                self.assertEqual(task["status"], "rolled_back")
                self.assertEqual(task["remote_rule_id"], "rule-42")
                self.assertIsNotNone(task["sla_completed_at_ms"])
                self.assertNotIn("verify", _ResponseConnectorHandler.operations)
                self.assertEqual(_ResponseConnectorHandler.operations[-1], "rollback")
            finally:
                _ResponseConnectorHandler.release_apply_response.set()
                _ResponseConnectorHandler.block_apply_response = False
                state.stop()

    def test_maintenance_reconciles_terminal_case_with_verified_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            try:
                connector = state.response_automation.save_connector(
                    {
                        "name": "Reconcile WAF",
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
                result = state.orchestrator.handle_alert(_waf_alert("response-reconcile-1"))
                approval = ApprovalResponseTaskTest._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "authorized"},
                )
                task_id = decided["response_task"]["task_id"]
                self.assertEqual(self._wait_for(state, task_id, "verified")["status"], "verified")
                state.response_automation.stop()

                with state.repo._lock:
                    state.repo.conn.execute(
                        "UPDATE cases SET status = 'closed' WHERE case_id = ?",
                        (result.case_id,),
                    )
                    state.repo.conn.commit()
                reconciled = state.repo.queue_terminal_case_response_rollbacks()

                self.assertEqual(reconciled, 1)
                self.assertEqual(
                    state.repo.get_response_task(task_id)["status"], "rollback_queued"
                )
            finally:
                state.stop()

    def test_late_verify_cannot_overwrite_terminal_case_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = self._state(tmp)
            _ResponseConnectorHandler.block_verify_response = True
            try:
                connector = state.response_automation.save_connector(
                    {
                        "name": "Verify Race WAF",
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
                result = state.orchestrator.handle_alert(_waf_alert("response-verify-race-1"))
                approval = ApprovalResponseTaskTest._executable_approval(state, result.case_id)
                decided = state.decide_approval(
                    approval["approval_id"],
                    {"decision": "approved", "actor": "approver", "reason": "authorized"},
                )
                task_id = decided["response_task"]["task_id"]
                self.assertTrue(_ResponseConnectorHandler.verify_received.wait(timeout=2))
                running = state.repo.get_response_task(task_id)
                self.assertEqual(running["status"], "running")
                self.assertEqual(running["remote_rule_id"], "rule-42")

                state.repo.update_case_status(result.case_id, "false_positive")
                self.assertEqual(
                    state.repo.get_response_task(task_id)["status"], "rollback_queued"
                )
                _ResponseConnectorHandler.release_verify_response.set()

                task = self._wait_for(state, task_id, "rolled_back")
                self.assertEqual(task["status"], "rolled_back")
                self.assertEqual(
                    _ResponseConnectorHandler.operations[-2:], ["verify", "rollback"]
                )
            finally:
                _ResponseConnectorHandler.release_verify_response.set()
                _ResponseConnectorHandler.block_verify_response = False
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
                    task_id,
                    "rollback_failed",
                    expected_status="verified",
                    error="temporary device outage",
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
        _ResponseConnectorHandler.block_apply_response = False
        _ResponseConnectorHandler.apply_received = threading.Event()
        _ResponseConnectorHandler.release_apply_response = threading.Event()
        _ResponseConnectorHandler.block_verify_response = False
        _ResponseConnectorHandler.verify_received = threading.Event()
        _ResponseConnectorHandler.release_verify_response = threading.Event()
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
            config.auth.principals = [
                AuthPrincipalConfig(
                    actor="config-only",
                    token="config-only-token-value",
                    roles=["config"],
                ),
                AuthPrincipalConfig(
                    actor="analyst-only",
                    token="analyst-only-token-value",
                    roles=["analyst"],
                ),
            ]
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

                for token in ("config-only-token-value", "analyst-only-token-value"):
                    status, _ = self._request(
                        base,
                        "/api/automation/playbooks",
                        token,
                    )
                    self.assertEqual(status, 200)
                    status, _ = self._request(
                        base,
                        "/api/automation/shadow-evaluations",
                        token,
                    )
                    self.assertEqual(status, 200)

                playbook_body = {
                    "playbook_id": "playbook_api_waf_block",
                    "name": "API WAF block",
                    "owner": "SOC Response",
                    "trigger_products": ["waf"],
                    "action_type": "network.block_ip",
                    "risk_tier": "high",
                    "sla_minutes": 20,
                    "publish": True,
                }
                status, _ = self._request(
                    base,
                    "/api/automation/playbooks",
                    config.auth.responder_token,
                    playbook_body,
                )
                self.assertEqual(status, 403)
                status, payload = self._request(
                    base,
                    "/api/automation/playbooks",
                    config.auth.api_token,
                    playbook_body,
                )
                self.assertEqual(status, 200)
                self.assertEqual(payload["playbook"]["status"], "active")
                status, payload = self._request(
                    base,
                    "/api/automation/playbooks?all_versions=true",
                    config.auth.responder_token,
                )
                self.assertEqual(status, 200)
                self.assertTrue(
                    any(
                        item["playbook_id"] == "playbook_api_waf_block"
                        for item in payload["playbooks"]
                    )
                )

                status, _ = self._request(
                    base,
                    "/api/automation/tasks/missing-task/operations",
                    config.auth.approver_token,
                    {"assignee": "approver"},
                )
                self.assertEqual(status, 403)
                status, _ = self._request(
                    base,
                    "/api/automation/tasks/missing-task/operations",
                    config.auth.responder_token,
                    {"assignee": "soc-responder"},
                )
                self.assertEqual(status, 404)
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
