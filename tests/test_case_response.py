from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from defensive_ai_gateway.app import GatewayState, build_server
from defensive_ai_gateway.case_response import _analysis_facts
from defensive_ai_gateway.config import AuthPrincipalConfig, GatewayConfig
from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.models import RawAlert, now_ms


def _waf_alert(alert_id: str) -> RawAlert:
    payload = json.loads(Path("samples/waf_alert.json").read_text(encoding="utf-8"))
    payload["payload"]["src_ip"] = "43.154.138.159"
    return RawAlert(
        source=payload["source"],
        product=payload["product"],
        event_type=payload["event_type"],
        severity=payload["severity"],
        timestamp=payload["timestamp"],
        payload=payload["payload"],
        alert_id=alert_id,
        trusted_sample=True,
    )


class CaseResponseServiceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        config = GatewayConfig()
        config.database.path = str(Path(self.directory.name) / "gateway.db")
        config.processing.async_enabled = False
        self.state = GatewayState(config)

    def tearDown(self):
        self.state.stop()
        self.directory.cleanup()

    def _case(self, alert_id: str = "case-response-1") -> str:
        return self.state.orchestrator.handle_alert(_waf_alert(alert_id)).case_id

    def test_versioned_pack_is_cited_and_never_executes_or_sends(self):
        case_id = self._case()
        tasks_before = self.state.repo.count_response_tasks()

        first = self.state.case_response.generate(case_id, actor="soc-analyst")
        self.assertTrue(first["created"])
        self.assertEqual(first["artifact"]["version"], 1)
        self.assertEqual(self.state.repo.count_response_tasks(), tasks_before)

        artifact = first["artifact"]
        pack = artifact["content"]
        self.assertTrue(artifact["evidence_refs"])
        self.assertLessEqual(
            len(pack["case_summary"]["headline_evidence_refs"]), 8
        )
        self.assertFalse(pack["execution_boundary"]["direct_execution"])
        self.assertFalse(
            pack["execution_boundary"]["direct_communication_delivery"]
        )
        self.assertEqual(
            pack["incident_communication"]["delivery_state"], "not_sent"
        )
        self.assertEqual(
            pack["incident_communication"]["known_facts"],
            pack["case_summary"]["key_facts"],
        )
        confirmed = pack["case_summary"]["key_facts"]
        self.assertEqual(confirmed[0]["claim_type"], "analysis_finding")
        self.assertEqual(confirmed[0]["status"], "risk")
        self.assertIn("请求特征：", confirmed[0]["text"])
        self.assertTrue(
            any(
                item["claim_type"] == "analysis_finding"
                and item["dimension"] == "参数/Header"
                and "SQL boolean expression markers" in item["text"]
                for item in confirmed
            )
        )
        self.assertEqual(confirmed[-1]["claim_type"], "security_event")
        self.assertEqual(pack["containment"]["allowed_action_types"], ["network.block_ip"])

        option = pack["containment"]["options"][0]
        self.assertEqual(option["required_connector_capability"], "network.source_ip")
        self.assertEqual(option["scope_guarantee"], "source_ip_and_ttl_only")
        self.assertIn("host", option["scope"]["context_only"])
        candidate = pack["containment"]["fine_grained_candidate"]
        self.assertEqual(candidate["state"], "blocked")
        self.assertFalse(candidate["routing_eligible"])
        self.assertEqual(
            candidate["required_connector_capability"], "waf.host_path.source_ip"
        )

        reused = self.state.case_response.generate(case_id, actor="soc-analyst")
        self.assertFalse(reused["created"])
        self.assertEqual(reused["artifact"]["artifact_id"], artifact["artifact_id"])
        self.assertEqual(reused["artifact"]["version"], 1)

        self.state.repo.update_case_status(case_id, "under_review")
        stale = self.state.case_response.latest(case_id)
        self.assertTrue(stale["freshness"]["is_stale"])
        second = self.state.case_response.generate(case_id, actor="soc-analyst")
        self.assertTrue(second["created"])
        self.assertEqual(second["artifact"]["version"], 2)

    def test_timeline_uses_sql_pagination_and_dual_clock_fallback(self):
        case_id = self._case("case-response-timeline")
        event_id = self.state.repo.get_case_response_source(case_id)["events"][0][
            "event_id"
        ]
        self.state.repo.conn.execute(
            "UPDATE normalized_events SET timestamp = 'invalid-time', event_at_ms = 1 "
            "WHERE event_id = ?",
            (event_id,),
        )
        self.state.repo.conn.commit()

        with patch.object(
            self.state.repo,
            "get_case_response_source",
            side_effect=AssertionError("timeline must not load the full Case snapshot"),
        ):
            first = self.state.case_response.timeline(case_id, limit=2, offset=0)
            second = self.state.case_response.timeline(case_id, limit=2, offset=2)
            repeated = self.state.case_response.timeline(case_id, limit=2, offset=0)

        self.assertGreaterEqual(first["pagination"]["total"], 4)
        self.assertEqual(first["items"], repeated["items"])
        self.assertFalse(
            {item["entry_id"] for item in first["items"]}
            & {item["entry_id"] for item in second["items"]}
        )
        event = next(
            item
            for page in (first, second)
            for item in page["items"]
            if item["entry_id"] == f"event:{event_id}"
        )
        self.assertEqual(event["time_basis"], "ingest_fallback")
        self.assertEqual(event["occurred_at_ms"], event["recorded_at_ms"])

    def test_timeline_exposes_actor_created_state_and_response_pack_audit(self):
        case_id = self._case("case-response-actor")
        event_id = self.state.repo.get_case_response_source(case_id)["events"][0][
            "event_id"
        ]
        timestamp = now_ms()
        approval_id = "approval-case-response-actor"
        self.state.repo.conn.execute(
            """
            INSERT INTO action_approvals(
              approval_id, case_id, event_id, action_json, status,
              requested_by, decided_by, created_at_ms, updated_at_ms
            ) VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, ?)
            """,
            (
                approval_id,
                case_id,
                event_id,
                json.dumps({"action": "临时封禁来源 IP"}, ensure_ascii=False),
                "timeline-requester",
                "timeline-approver",
                timestamp,
                timestamp,
            ),
        )
        self.state.repo.conn.commit()
        self.state.repo.create_response_task(
            {
                "task_id": "task-case-response-actor",
                "approval_id": approval_id,
                "case_id": case_id,
                "event_id": event_id,
                "action_type": "network.block_ip",
                "action": {"object": "43.154.138.159/32", "duration_seconds": 1800},
                "status": "verified",
                "idempotency_key": "response-actor-idempotency",
                "created_by": "timeline-responder",
                "created_at_ms": timestamp,
            }
        )
        self.state.case_response.generate(case_id, actor="timeline-analyst")

        payload = self.state.case_response.timeline(case_id, limit=100, offset=0)
        task_created = next(
            item
            for item in payload["items"]
            if item["entry_id"] == "response-task:task-case-response-actor"
        )
        self.assertEqual(task_created["state"], "created")
        self.assertEqual(task_created["actor"], "timeline-responder")
        generated = next(
            item
            for item in payload["items"]
            if item["kind"] == "governance"
            and item["title"].endswith("case_response_pack_generated")
        )
        self.assertEqual(generated["actor"], "timeline-analyst")

    def test_schema_indexes_and_static_workbench_contract(self):
        indexes = {
            row["name"]
            for row in self.state.repo.conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        self.assertTrue(
            {
                "idx_memory_entries_created_id",
                "idx_memory_events_created_id",
                "idx_response_tasks_created_id",
                "idx_case_response_artifacts_case",
            }.issubset(indexes)
        )
        html = Path("defensive_ai_gateway/static/case-response.html").read_text(
            encoding="utf-8"
        )
        script = Path("defensive_ai_gateway/static/case-response.js").read_text(
            encoding="utf-8"
        )
        css = Path("defensive_ai_gateway/static/style.css").read_text(
            encoding="utf-8"
        )
        app_script = Path("defensive_ai_gateway/static/app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("case-response-timeline", html)
        self.assertIn("fine_grained_candidate", script)
        self.assertIn('roles.includes("analyst")', script)
        self.assertIn("communicationList(draft.known_facts", script)
        self.assertIn("factPresentation(fact)", script)
        self.assertIn("dimension || tr(\"eventRecord\")", script)
        self.assertNotIn("AI 研判结论", script)
        self.assertIn("case-response-overview-evidence", script)
        self.assertIn("const evidenceBlock = refs(summary.headline_evidence_refs)", script)
        self.assertNotIn("${refs(summary.headline_evidence_refs)}", script)
        self.assertNotIn("${refs(fact.evidence_refs)}", script)
        self.assertNotIn("${refs(step.evidence_refs)}", script)
        self.assertNotIn("${refs(value.evidence_refs)}", script)
        self.assertIn("case-response-summary-facts", script)
        self.assertIn("case-response-summary-uncertainties", script)
        self.assertIn("case-response-summary-pending", script)
        self.assertIn("copyCommunicationReport", script)
        self.assertIn('addEventListener("click", copyCommunicationReport)', script)
        self.assertIn("timelinePageMustReset", script)
        self.assertIn("AbortController", script)
        self.assertIn("candidateScope", script)
        self.assertIn("step.success_criteria", script)
        self.assertIn("item.rollback", script)
        self.assertIn('id="case-response-copy-report"', html)
        self.assertIn('aria-busy="false"', html)
        self.assertNotIn("case-response-communication-grid", css)
        self.assertRegex(
            css,
            r"(?s)\.case-response-timeline-head > strong\s*\{[^}]*"
            r"flex: 1 1 auto;[^}]*min-width: 0;",
        )
        self.assertRegex(
            css,
            r"(?s)\.case-response-timeline-badges\s*\{[^}]*"
            r"flex: 0 0 auto;[^}]*flex-wrap: wrap;",
        )
        self.assertRegex(
            css,
            r"(?s)\.case-response-state,\s*\.case-response-kind\s*\{[^}]*"
            r"flex: 0 0 auto;[^}]*white-space: nowrap;",
        )
        self.assertRegex(
            css,
            r"(?s)\.case-response-report-progress\s*\{[^}]*display: grid;",
        )
        self.assertRegex(
            css,
            r"(?s)\.case-response-summary-grid\s*\{[^}]*"
            r"grid-template-columns: repeat\(2, minmax\(0, 1fr\)\);",
        )
        self.assertRegex(
            css,
            r"(?s)\.case-response-summary-facts\s*\{[^}]*"
            r"grid-column: 1 / -1;[^}]*border-bottom:",
        )
        self.assertRegex(
            css,
            r"(?s)\.case-response-summary-pending\s*\{[^}]*"
            r"padding-left: 18px;[^}]*border-left:",
        )
        self.assertRegex(
            css,
            r"(?s)\.case-response-overview-evidence\s*\{[^}]*"
            r"grid-column: 1 / -1;[^}]*padding-top: 9px;",
        )
        self.assertIn("response-pack-link", app_script)
        self.assertNotIn("direct_communication_delivery: true", script)

    def test_confirmed_facts_exclude_review_and_uncertain_info_dimensions(self):
        facts = _analysis_facts(
            {
                "explanation": {
                    "dimensions": [
                        {
                            "title": "参数特征",
                            "status": "risk",
                            "evidence": "输入包含已识别的表达式对象构造与方法调用链。",
                        },
                        {
                            "title": "危险调用",
                            "status": "risk",
                            "evidence": "调用栈已触达 java.io.File.list。",
                        },
                        {
                            "title": "成功与危害",
                            "status": "review",
                            "evidence": "尚未确认响应是否返回目录内容。",
                        },
                        {
                            "title": "上下文",
                            "status": "info",
                            "evidence": "缺少应用主机审计。",
                        },
                        {
                            "title": "规则匹配",
                            "status": "info",
                            "evidence": "cloudrasp_list_file_102 与目录枚举调用一致。",
                        },
                    ]
                }
            },
            analyzed_at_ms=123,
            evidence_refs=["event-1:rule_id"],
        )

        self.assertEqual(
            [item["dimension"] for item in facts],
            ["参数特征", "危险调用", "规则匹配"],
        )
        self.assertTrue(all(item["claim_type"] == "analysis_finding" for item in facts))
        self.assertTrue(all(item["evidence_refs"] == ["event-1:rule_id"] for item in facts))

    def test_static_responsive_contract_covers_target_viewports(self):
        html = Path("defensive_ai_gateway/static/case-response.html").read_text(
            encoding="utf-8"
        )
        css = Path("defensive_ai_gateway/static/style.css").read_text(
            encoding="utf-8"
        )
        script = Path("defensive_ai_gateway/static/case-response.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('name="viewport" content="width=device-width, initial-scale=1"', html)
        self.assertIn(".case-response-page {\n  min-width: 320px;", css)
        self.assertIn("width: min(100% - 48px, 1240px);", css)
        self.assertIn("@media (max-width: 900px)", css)
        self.assertIn("@media (max-width: 640px)", css)
        self.assertRegex(
            css,
            r"(?s)@media \(max-width: 900px\).*?\.case-response-overview,\s*"
            r"\.case-response-summary-grid\s*\{\s*grid-template-columns: 1fr;",
        )
        self.assertRegex(
            css,
            r"(?s)@media \(max-width: 640px\).*?\.case-response-actions\s*\{[^}]*"
            r"grid-template-columns: repeat\(2, minmax\(0, 1fr\)\);",
        )
        for heading_key in (
            "summaryHeading",
            "containmentHeading",
            "playbookHeading",
            "communicationHeading",
            "timelineHeading",
        ):
            self.assertEqual(script.count(f'{heading_key}: "'), 2)

    def test_v16_rejects_an_incomplete_v15_response_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "incomplete.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE schema_version(
                  version INTEGER PRIMARY KEY,
                  applied_at_ms INTEGER NOT NULL
                );
                INSERT INTO schema_version(version, applied_at_ms) VALUES (15, 1);
                CREATE TABLE response_connectors(connector_id TEXT PRIMARY KEY);
                """
            )
            connection.close()

            with self.assertRaisesRegex(
                RuntimeError, "response automation table is incomplete"
            ):
                Repository(str(path))


class CaseResponseHTTPRoleTest(unittest.TestCase):
    @staticmethod
    def _request(base: str, path: str, token: str, body: dict | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
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

    def test_analyst_generates_while_approver_and_responder_are_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.server.host = "127.0.0.1"
            config.server.port = 0
            config.processing.async_enabled = False
            config.auth.operator_token = "operator-token-value"
            config.auth.approver_token = "approver-token-value"
            config.auth.responder_token = "responder-token-value"
            config.auth.principals = [
                AuthPrincipalConfig("read-only", "read-only-token", {"read"})
            ]
            server = build_server(config)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                case_id = server.state.orchestrator.handle_alert(
                    _waf_alert("case-response-http")
                ).case_id
                path = f"/api/cases/{case_id}/response-pack/generate"

                for token in (
                    config.auth.approver_token,
                    config.auth.responder_token,
                    "read-only-token",
                ):
                    status, _ = self._request(base, path, token, {})
                    self.assertEqual(status, 403)
                status, payload = self._request(
                    base, path, config.auth.operator_token, {"actor": "forged-actor"}
                )
                self.assertEqual(status, 201)
                self.assertTrue(payload["created"])
                self.assertEqual(payload["artifact"]["created_by"], "soc-operator")

                for token in (
                    config.auth.operator_token,
                    config.auth.approver_token,
                    config.auth.responder_token,
                    "read-only-token",
                ):
                    status, payload = self._request(
                        base,
                        f"/api/cases/{case_id}/response-pack/latest",
                        token,
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(payload["artifact"]["version"], 1)
                    status, timeline = self._request(
                        base,
                        f"/api/cases/{case_id}/timeline?limit=5&offset=0",
                        token,
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(timeline["case"]["case_id"], case_id)

                for unauthorized in ("", "invalid-token"):
                    status, _ = self._request(
                        base,
                        f"/api/cases/{case_id}/response-pack/latest",
                        unauthorized,
                    )
                    self.assertEqual(status, 401)
                    status, _ = self._request(
                        base,
                        f"/api/cases/{case_id}/timeline",
                        unauthorized,
                    )
                    self.assertEqual(status, 401)
                    status, _ = self._request(base, path, unauthorized, {})
                    self.assertEqual(status, 401)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
