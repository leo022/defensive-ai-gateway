from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from defensive_ai_gateway.app import GatewayState, build_server
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.models import RawAlert


def _waf_alert(alert_id: str) -> RawAlert:
    payload = json.loads(Path("samples/waf_alert.json").read_text(encoding="utf-8"))
    payload["alert_id"] = alert_id
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


def _config(database_path: Path, *, quorum: int = 1) -> GatewayConfig:
    config = GatewayConfig()
    config.database.path = str(database_path)
    config.processing.async_enabled = False
    config.policy.approval_quorum = quorum
    return config


class AgentHarnessControlTest(unittest.TestCase):
    def _queued_session(self, state: GatewayState, alert_id: str) -> dict:
        case_id = state.orchestrator.handle_alert(_waf_alert(alert_id)).case_id
        artifact = state.case_response.generate(case_id, actor="analyst")["artifact"]
        started = state.response_agent.create(
            case_id,
            artifact=artifact,
            goal="Verify immutable harness configuration",
            actor="analyst",
        )
        return state.repo.get_response_agent_session(started["session_id"])

    def test_draft_publish_and_existing_session_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = GatewayState(_config(Path(tmp) / "gateway.db"))
            try:
                state.response_agent.stop()
                initial = state.agent_harness_payload()["active"]
                self.assertEqual(initial["version"], 1)
                self.assertEqual(initial["status"], "active")
                self.assertEqual(len(state.agent_harness_payload()["fixed_controls"]), 7)

                existing = self._queued_session(state, "harness-before-publish")
                original_turns = existing["budget"]["max_turns"]
                self.assertEqual(existing["model_metadata"]["harness_profile_version"], 1)
                state.response_agent.cancel(existing["session_id"], actor="analyst")

                draft_result = state.save_agent_harness_profile(
                    {
                        "name": "Response Investigation Harness",
                        "description": "Raise the turn budget for new sessions",
                        "settings": {
                            "response_agent": {"max_turns": original_turns + 8},
                            "approval": {"quorum": 1},
                        },
                        "_actor": "config-admin",
                    }
                )
                draft = draft_result["profile"]
                self.assertEqual(draft["status"], "draft")
                self.assertEqual(state.config.response_agent.max_turns, original_turns)

                published = state.publish_agent_harness_profile(
                    draft["version"], actor="config-admin"
                )["profile"]
                self.assertEqual(published["status"], "active")
                self.assertEqual(
                    state.config.response_agent.max_turns, original_turns + 8
                )

                unchanged = state.repo.get_response_agent_session(existing["session_id"])
                self.assertEqual(unchanged["budget"]["max_turns"], original_turns)
                self.assertEqual(
                    unchanged["model_metadata"]["harness_profile_version"], 1
                )
                new_session = self._queued_session(state, "harness-after-publish")
                self.assertEqual(new_session["budget"]["max_turns"], original_turns + 8)
                self.assertEqual(
                    new_session["model_metadata"]["harness_profile_version"],
                    draft["version"],
                )
            finally:
                state.stop()

    def test_restart_restores_published_profile_without_new_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "gateway.db"
            first = GatewayState(_config(database_path))
            try:
                draft = first.save_agent_harness_profile(
                    {
                        "name": "Persistent Harness",
                        "settings": {"response_agent": {"max_wall_seconds": 1_200}},
                        "_actor": "config-admin",
                    }
                )["profile"]
                first.publish_agent_harness_profile(
                    draft["version"], actor="config-admin"
                )
            finally:
                first.stop()

            restarted = GatewayState(_config(database_path))
            try:
                payload = restarted.agent_harness_payload()
                self.assertEqual(payload["active"]["version"], draft["version"])
                self.assertEqual(len(payload["versions"]), 2)
                self.assertEqual(restarted.config.response_agent.max_wall_seconds, 1_200)
            finally:
                restarted.stop()

    def test_locked_fields_and_deployment_quorum_floor_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = GatewayState(_config(Path(tmp) / "gateway.db", quorum=2))
            try:
                with self.assertRaisesRegex(ValueError, "locked or unknown"):
                    state.save_agent_harness_profile(
                        {
                            "name": "Unsafe Harness",
                            "settings": {
                                "response_agent": {"enabled": False},
                                "approval": {"quorum": 2},
                            },
                            "_actor": "config-admin",
                        }
                    )
                with self.assertRaisesRegex(ValueError, "between 2 and 2"):
                    state.save_agent_harness_profile(
                        {
                            "name": "Lowered Approval Harness",
                            "settings": {"approval": {"quorum": 1}},
                            "_actor": "config-admin",
                        }
                    )
                with self.assertRaisesRegex(ValueError, "max_turns must be an integer"):
                    state.save_agent_harness_profile(
                        {
                            "name": "Fractional Harness",
                            "settings": {
                                "response_agent": {"max_turns": 48.5},
                                "approval": {"quorum": 2},
                            },
                            "_actor": "config-admin",
                        }
                    )
                self.assertEqual(len(state.agent_harness_payload()["versions"]), 1)
            finally:
                state.stop()


class AgentHarnessHTTPRoleTest(unittest.TestCase):
    @staticmethod
    def _request(base: str, path: str, token: str, data=None):
        body = json.dumps(data).encode("utf-8") if data is not None else None
        request = urllib.request.Request(
            f"{base}{path}",
            data=body,
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

    def test_config_role_is_required_to_draft_and_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _config(Path(tmp) / "gateway.db")
            config.server.host = "127.0.0.1"
            config.server.port = 0
            config.auth.api_token = "admin-harness-token"
            config.auth.operator_token = "operator-harness-token"
            server = build_server(config)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                status, _ = self._request(
                    base,
                    "/api/config/agent-harness",
                    config.auth.operator_token,
                )
                self.assertEqual(status, 403)

                status, payload = self._request(
                    base,
                    "/api/config/agent-harness",
                    config.auth.api_token,
                )
                self.assertEqual(status, 200)
                self.assertTrue(payload["change_scope"]["existing_sessions_immutable"])

                status, draft = self._request(
                    base,
                    "/api/config/agent-harness",
                    config.auth.api_token,
                    {
                        "name": "HTTP Harness",
                        "description": "API contract check",
                        "settings": {"response_agent": {"max_turns": 56}},
                    },
                )
                self.assertEqual(status, 201)
                self.assertEqual(draft["profile"]["status"], "draft")

                version = draft["profile"]["version"]
                status, published = self._request(
                    base,
                    f"/api/config/agent-harness/{version}/publish",
                    config.auth.api_token,
                    {},
                )
                self.assertEqual(status, 200)
                self.assertEqual(published["active"]["version"], version)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
