from __future__ import annotations

import hashlib
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.database import AlertIdentityConflict, Repository
from defensive_ai_gateway.json_safety import MAX_JSON_NESTING, MAX_JSON_NODES
from defensive_ai_gateway.llm import LLMClient, LLMEndpointConfigurationError, LocalHeuristicLLM
from defensive_ai_gateway.log_adapter import LogAdapter
from defensive_ai_gateway.memory import MemoryManager
from defensive_ai_gateway.models import RawAlert
from defensive_ai_gateway.normalizer import EventNormalizer
from defensive_ai_gateway.orchestrator import Orchestrator
from defensive_ai_gateway.policy import PolicyEngine
from defensive_ai_gateway.processing import (
    AlertNonRetryableError,
    AlertProcessor,
    AlertQueueFull,
    AlertRetryableError,
    DeadLetter,
)
from defensive_ai_gateway.syslog_receiver import (
    SyslogFrameDecoder,
    SyslogFrameError,
    SyslogListenerSpec,
    SyslogReceiverManager,
    _SyslogListener,
)
from defensive_ai_gateway.syslog_router import SyslogPortRouter
from scripts.simulate_syslog_ports import _embedded_expected_alert, _send_to_embedded_listeners


ROOT = Path(__file__).resolve().parents[1]


def _alert(alert_id: str = "reliability-001") -> RawAlert:
    return RawAlert(
        source="test",
        product="waf",
        event_type="reliability_test",
        severity="high",
        timestamp="2026-07-14T10:00:00+08:00",
        payload={"uri": "/health"},
        alert_id=alert_id,
    )


class AlertProcessorReliabilityTest(unittest.TestCase):
    def test_transient_failure_is_retried_then_processed(self):
        calls: list[str] = []

        def handler(alert: RawAlert) -> None:
            calls.append(alert.alert_id)
            if len(calls) < 3:
                raise RuntimeError("temporary outage")

        processor = AlertProcessor(
            handler,
            workers=1,
            max_attempts=3,
            retry_base_delay=0,
        )
        processor.start()
        processor.submit(_alert())

        self.assertTrue(processor.wait_for_idle(timeout=1))
        stats = processor.stats()
        self.assertEqual(len(calls), 3)
        self.assertEqual(stats.processed, 1)
        self.assertEqual(stats.retried, 2)
        self.assertEqual(stats.failed, 0)
        self.assertEqual(stats.dead_lettered, 0)
        self.assertTrue(processor.stop(timeout=1))

    def test_health_detects_stopped_worker_pool(self):
        processor = AlertProcessor(lambda _alert: None, workers=1)
        self.assertFalse(processor.is_healthy())
        processor.start()
        self.assertTrue(processor.is_healthy())
        self.assertTrue(processor.stop(timeout=1))
        self.assertFalse(processor.is_healthy())

    def test_exhausted_failure_calls_dlq_hook_and_keeps_local_copy(self):
        delivered: list[DeadLetter] = []
        processor = AlertProcessor(
            lambda _alert: (_ for _ in ()).throw(RuntimeError("database unavailable")),
            workers=1,
            max_attempts=2,
            retry_base_delay=0,
            dead_letter_handler=delivered.append,
        )
        processor.start()
        processor.submit(_alert("dlq-001"))

        self.assertTrue(processor.wait_for_idle(timeout=1))
        stats = processor.stats()
        self.assertEqual(stats.retried, 1)
        self.assertEqual(stats.failed, 1)
        self.assertEqual(stats.dead_lettered, 1)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0].alert.alert_id, "dlq-001")
        self.assertEqual(delivered[0].attempts, 2)
        self.assertEqual(delivered[0].reason, "handler_error")
        self.assertEqual(delivered[0].to_dict()["alert"]["payload"], {"uri": "/health"})
        self.assertEqual(processor.dead_letters()[0], delivered[0])
        self.assertTrue(processor.stop(timeout=1))

    def test_retryable_failure_preserves_its_durable_delay(self):
        delivered: list[DeadLetter] = []
        processor = AlertProcessor(
            lambda _alert: (_ for _ in ()).throw(
                AlertRetryableError("remote model unavailable", retry_after_seconds=12)
            ),
            workers=1,
            max_attempts=1,
            retry_base_delay=0,
            dead_letter_handler=delivered.append,
        )
        processor.start()
        processor.submit(_alert("retryable-llm-001"))

        self.assertTrue(processor.wait_for_idle(timeout=1))
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0].retry_after_seconds, 12)
        self.assertEqual(delivered[0].to_dict()["retry_after_seconds"], 12)
        self.assertTrue(processor.stop(timeout=1))

    def test_permanent_failure_enters_dlq_without_in_memory_retry(self):
        delivered: list[DeadLetter] = []
        calls = 0

        def handler(_alert: RawAlert) -> None:
            nonlocal calls
            calls += 1
            raise AlertNonRetryableError("invalid credential")

        processor = AlertProcessor(
            handler,
            workers=1,
            max_attempts=5,
            retry_base_delay=0,
            dead_letter_handler=delivered.append,
        )
        processor.start()
        processor.submit(_alert("permanent-001"))

        self.assertTrue(processor.wait_for_idle(timeout=1))
        self.assertEqual(calls, 1)
        self.assertEqual(processor.stats().retried, 0)
        self.assertEqual(delivered[0].reason, "non_retryable")
        self.assertTrue(processor.stop(timeout=1))

    def test_shutdown_deadline_moves_not_started_alert_to_dlq(self):
        started = threading.Event()
        release = threading.Event()

        def handler(_alert: RawAlert) -> None:
            started.set()
            release.wait(1)

        processor = AlertProcessor(handler, max_size=2, workers=1, max_attempts=1)
        processor.start()
        processor.submit(_alert("busy"))
        self.assertTrue(started.wait(1))
        processor.submit(_alert("pending"))

        started_at = time.monotonic()
        self.assertFalse(processor.stop(timeout=0.02))
        self.assertLess(time.monotonic() - started_at, 0.25)
        dead_letters = processor.dead_letters()
        self.assertEqual([entry.alert.alert_id for entry in dead_letters], ["pending"])
        self.assertEqual(dead_letters[0].reason, "shutdown_timeout")

        release.set()
        self.assertTrue(processor.wait_for_idle(timeout=1))


class MaintenanceReadinessTest(unittest.TestCase):
    def test_repeated_stale_maintenance_failures_make_readiness_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                self.assertTrue(state.readiness()["checks"]["maintenance"]["ok"])
                state._maintenance_consecutive_failures = 3
                state._maintenance_last_error = "OperationalError"
                state._maintenance_last_success_ms = 0
                readiness = state.readiness()
                self.assertFalse(readiness["ok"])
                self.assertFalse(readiness["checks"]["maintenance"]["ok"])
                self.assertEqual(
                    readiness["checks"]["maintenance"]["last_error"],
                    "OperationalError",
                )
            finally:
                state.stop()


class AlertIdentityHandlingTest(unittest.TestCase):
    def test_submit_alert_marks_exact_replay_and_rejects_conflicting_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                original = _alert("alert-identity-state-001")
                first = state.submit_alert(original)

                replay = state.submit_alert(_alert("alert-identity-state-001"))
                self.assertTrue(replay["duplicate"])
                self.assertEqual(replay["idempotency"]["outcome"], "reused_existing_alert")
                self.assertEqual(replay["case_id"], first["case_id"])

                conflicting = _alert("alert-identity-state-001")
                conflicting.timestamp = "2026-07-14T10:05:00+08:00"
                with self.assertRaises(AlertIdentityConflict):
                    state.submit_alert(conflicting)

                self.assertEqual(
                    state.repo.get_raw_alert(original.alert_id).timestamp,
                    original.timestamp,
                )
            finally:
                state.stop()


class RemoteLLMDeferralTest(unittest.TestCase):
    class _UnavailableRemoteLLM(LLMClient):
        @property
        def runtime_metadata(self) -> dict:
            return {
                "provider": "gateway",
                "model": "remote-test",
                "endpoint_host": "llm-gateway.example",
            }

        @property
        def defer_on_failure(self) -> bool:
            return True

        @property
        def retry_after_seconds(self) -> float:
            return 11.0

        def analyze(self, prompt: str, context: dict) -> dict:
            raise RuntimeError("simulated gateway outage")

    class _RecoveredRemoteLLM(LLMClient):
        @property
        def runtime_metadata(self) -> dict:
            return {
                "provider": "gateway",
                "model": "remote-test",
                "endpoint_host": "llm-gateway.example",
            }

        @property
        def defer_on_failure(self) -> bool:
            return True

        def analyze(self, prompt: str, context: dict) -> dict:
            return {
                "classification": "suspicious",
                "confidence": 0.84,
                "verdict": "【需人工复核】- 远程模型恢复后完成研判",
                "reason": "研判结论：【需人工复核】- 远程模型恢复后完成研判",
                "analysis_dimensions": [
                    {"title": "证据", "status": "review", "evidence": "保留的告警已重新提交"}
                ],
                "recommended_next_steps": [],
                "missing_evidence": [],
                "business_impact": "待人工复核",
            }

    class _WebSocketEndpointLLM(_UnavailableRemoteLLM):
        def analyze(self, prompt: str, context: dict) -> dict:
            raise LLMEndpointConfigurationError(
                "LLM gateway endpoint requires a WebSocket/Realtime protocol"
            )

    class _BlockingRemoteLLM(LLMClient):
        def __init__(self):
            self.started = threading.Event()
            self.release = threading.Event()
            self.context: dict | None = None

        @property
        def runtime_metadata(self) -> dict:
            return {
                "provider": "gateway",
                "model": "remote-test",
                "endpoint_host": "llm-gateway.example",
            }

        def analyze(self, prompt: str, context: dict) -> dict:
            self.context = context
            self.started.set()
            if not self.release.wait(2):
                raise RuntimeError("test did not release blocking model")
            return {
                "classification": "suspicious",
                "confidence": 0.84,
                "verdict": "【需人工复核】- 阻塞模型完成研判",
                "reason": "研判结论：【需人工复核】- 阻塞模型完成研判\n分析报告：证据待复核。",
                "analysis_dimensions": [
                    {"title": "证据", "status": "review", "evidence": "告警证据已保留"}
                ],
                "recommended_next_steps": [],
                "missing_evidence": [],
                "business_impact": "待人工复核",
            }

    @staticmethod
    def _wait_until(predicate, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return bool(predicate())

    def test_normalized_alert_is_visible_while_remote_analysis_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            llm = self._BlockingRemoteLLM()
            orchestrator = Orchestrator(
                repo,
                EventNormalizer(policy),
                MemoryManager(repo, policy),
                llm,
                policy,
            )
            outcome: dict = {}
            alert = _alert("remote-in-progress-001")

            def run_analysis() -> None:
                try:
                    outcome["result"] = orchestrator.handle_alert(alert)
                except Exception as exc:  # pragma: no cover - asserted below
                    outcome["error"] = exc

            started_at = time.monotonic()
            worker = threading.Thread(target=run_analysis)
            worker.start()
            try:
                self.assertTrue(llm.started.wait(1))
                provisional = repo.conn.execute(
                    """
                    SELECT c.*, l.alert_id, l.event_id
                    FROM cases c
                    JOIN case_alert_links l ON l.case_id = c.case_id
                    WHERE l.alert_id = ?
                    """,
                    (alert.alert_id,),
                ).fetchone()
                self.assertIsNotNone(provisional)
                self.assertLess(time.monotonic() - started_at, 1)
                self.assertEqual(provisional["status"], "analyzing")
                self.assertEqual(provisional["classification"], "pending_analysis")
                self.assertEqual(provisional["confidence"], 0)
                self.assertEqual(
                    repo.conn.execute(
                        "SELECT COUNT(*) FROM audit_log WHERE action = 'analysis_started'"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(llm.context["memory"]["evidence_refs"], [])
            finally:
                llm.release.set()
                worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertNotIn("error", outcome)
            result = outcome["result"]
            completed = repo.get_case(result.case_id)
            self.assertEqual(completed["status"], "open")
            self.assertEqual(completed["classification"], "suspicious")
            self.assertEqual(len(completed["linked_alerts"]), 1)
            self.assertEqual(len(completed["agent_runs"]), 1)

    def test_new_alert_does_not_overwrite_existing_case_disposition_while_analyzing(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            orchestrator = Orchestrator(
                repo,
                EventNormalizer(policy),
                MemoryManager(repo, policy),
                self._RecoveredRemoteLLM(),
                policy,
            )
            first = orchestrator.handle_alert(_alert("remote-correlated-001"))
            repo.update_case_status(first.case_id, "under_review")

            llm = self._BlockingRemoteLLM()
            orchestrator.llm = llm
            outcome: dict = {}

            def run_analysis() -> None:
                try:
                    outcome["result"] = orchestrator.handle_alert(
                        _alert("remote-correlated-002")
                    )
                except Exception as exc:  # pragma: no cover - asserted below
                    outcome["error"] = exc

            worker = threading.Thread(target=run_analysis)
            worker.start()
            try:
                self.assertTrue(llm.started.wait(1))
                in_progress = repo.get_case(first.case_id)
                self.assertEqual(in_progress["status"], "under_review")
                self.assertEqual(in_progress["classification"], "suspicious")
                self.assertEqual(len(in_progress["linked_alerts"]), 2)
                self.assertEqual(len(in_progress["agent_runs"]), 1)
            finally:
                llm.release.set()
                worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertNotIn("error", outcome)
            completed = repo.get_case(first.case_id)
            self.assertEqual(completed["status"], "under_review")
            self.assertEqual(len(completed["linked_alerts"]), 2)
            self.assertEqual(len(completed["agent_runs"]), 2)

    def test_remote_model_failure_is_durable_and_does_not_use_local_heuristic(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            orchestrator = Orchestrator(
                repo,
                EventNormalizer(policy),
                MemoryManager(repo, policy),
                self._UnavailableRemoteLLM(),
                policy,
            )

            with self.assertRaises(AlertRetryableError) as raised:
                orchestrator.handle_alert(_alert("remote-deferred-001"))

            self.assertEqual(raised.exception.retry_after_seconds, 11)
            raw_count = repo.conn.execute(
                "SELECT COUNT(*) AS count FROM raw_alerts WHERE alert_id = ?",
                ("remote-deferred-001",),
            ).fetchone()["count"]
            event_count = repo.conn.execute(
                "SELECT COUNT(*) AS count FROM normalized_events WHERE alert_id = ?",
                ("remote-deferred-001",),
            ).fetchone()["count"]
            run_count = repo.conn.execute("SELECT COUNT(*) AS count FROM agent_runs").fetchone()["count"]
            audit = repo.conn.execute(
                "SELECT detail_json FROM audit_log WHERE action = 'analysis_deferred'"
            ).fetchone()

            self.assertEqual(raw_count, 1)
            self.assertEqual(event_count, 1)
            self.assertEqual(run_count, 0)
            self.assertIsNotNone(audit)
            self.assertIn('"provider": "gateway"', audit["detail_json"])
            provisional = repo.conn.execute(
                """
                SELECT c.* FROM cases c
                JOIN case_alert_links l ON l.case_id = c.case_id
                WHERE l.alert_id = ?
                """,
                ("remote-deferred-001",),
            ).fetchone()
            self.assertIsNotNone(provisional)
            self.assertEqual(provisional["status"], "analysis_deferred")
            self.assertEqual(provisional["classification"], "pending_analysis")

    def test_websocket_endpoint_error_is_terminal_and_not_durably_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            repo = Repository(str(Path(tmp) / "gateway.db"))
            policy = PolicyEngine(config.policy)
            orchestrator = Orchestrator(
                repo,
                EventNormalizer(policy),
                MemoryManager(repo, policy),
                self._WebSocketEndpointLLM(),
                policy,
            )

            with self.assertRaises(LLMEndpointConfigurationError):
                orchestrator.handle_alert(_alert("websocket-config-001"))

            deferred = repo.conn.execute(
                "SELECT COUNT(*) AS count FROM audit_log WHERE action = 'analysis_deferred'"
            ).fetchone()["count"]
            failed = repo.conn.execute(
                "SELECT detail_json FROM audit_log WHERE action = 'analysis_failed'"
            ).fetchone()

            self.assertEqual(deferred, 0)
            self.assertIsNotNone(failed)
            self.assertIn('"fallback": "not_used"', failed["detail_json"])
            provisional = repo.conn.execute(
                """
                SELECT c.status, c.classification FROM cases c
                JOIN case_alert_links l ON l.case_id = c.case_id
                WHERE l.alert_id = ?
                """,
                ("websocket-config-001",),
            ).fetchone()
            self.assertEqual(provisional["status"], "analysis_failed")
            self.assertEqual(provisional["classification"], "pending_analysis")

    def test_async_terminal_remote_error_enters_durable_dlq_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = True
            config.processing.workers = 1
            config.processing.max_attempts = 12
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                terminal = self._WebSocketEndpointLLM()
                state.llm = terminal
                state.orchestrator.llm = terminal
                alert = _alert("terminal-remote-dlq-001")
                state.submit_alert(alert)
                self.assertTrue(
                    self._wait_until(
                        lambda: bool(
                            (record := state.repo.get_inbox_alert(alert.alert_id))
                            and record["status"] == "dead_letter"
                        )
                    )
                )
                record = state.repo.get_inbox_alert(alert.alert_id)
                self.assertEqual(record["attempts"], 1)
                self.assertEqual(
                    state.repo.conn.execute(
                        "SELECT COUNT(*) FROM audit_log "
                        "WHERE action = 'analysis_deferred'"
                    ).fetchone()[0],
                    0,
                )
            finally:
                state.stop()

    def test_gateway_replays_deferred_alert_once_after_manual_remote_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = True
            config.processing.workers = 1
            config.processing.retry_base_seconds = 0.1
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                unavailable = self._UnavailableRemoteLLM()
                state.llm = unavailable
                state.orchestrator.llm = unavailable
                alert = _alert("remote-deferred-recovery-001")
                state.submit_alert(alert)

                self.assertTrue(
                    self._wait_until(
                        lambda: bool(
                            (record := state.repo.get_inbox_alert(alert.alert_id))
                            and record["status"] == "deferred"
                            and record["analysis_deferred"]
                        )
                    )
                )
                deferred = state.repo.get_inbox_alert(alert.alert_id)
                self.assertIsNotNone(deferred)
                self.assertEqual(deferred["attempts"], 0)
                provisional = state.repo.conn.execute(
                    """
                    SELECT c.case_id, c.status FROM cases c
                    JOIN case_alert_links l ON l.case_id = c.case_id
                    WHERE l.alert_id = ?
                    """,
                    (alert.alert_id,),
                ).fetchone()
                self.assertEqual(provisional["status"], "analysis_deferred")
                provisional_case_id = provisional["case_id"]
                self.assertEqual(state.processing_stats()["llm_deferred"]["deferred"], 1)
                self.assertEqual(
                    state.repo.release_llm_deferred_alerts(limit=10, force=False)["released"],
                    0,
                )

                recovered = self._RecoveredRemoteLLM()
                state.llm = recovered
                state.orchestrator.llm = recovered
                released = state.release_llm_deferred_alerts(
                    limit=10,
                    actor="test-analyst",
                    force=True,
                )
                self.assertEqual(released["released"], 1)
                self.assertTrue(
                    self._wait_until(
                        lambda: bool(
                            (record := state.repo.get_inbox_alert(alert.alert_id))
                            and record["status"] == "completed"
                        )
                    )
                )
                self.assertEqual(
                    state.repo.conn.execute(
                        "SELECT COUNT(*) AS count FROM agent_runs"
                    ).fetchone()["count"],
                    1,
                )
                completed = state.repo.get_case(provisional_case_id)
                self.assertEqual(completed["status"], "open")
                self.assertEqual(len(completed["linked_alerts"]), 1)
                self.assertEqual(
                    state.release_llm_deferred_alerts(limit=10, actor="test-analyst")["released"],
                    0,
                )
            finally:
                state.stop()

    def test_scheduled_recovery_does_not_replay_legacy_llm_dead_letters(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            alert = _alert("legacy-remote-deferred-001")
            repo.enqueue_alert(alert, max_attempts=1)
            repo.conn.execute(
                """
                UPDATE durable_alert_inbox
                SET status = 'dead_letter', last_error = 'remote LLM analysis deferred for durable retry'
                WHERE alert_id = ?
                """,
                (alert.alert_id,),
            )
            repo.conn.commit()

            scheduled = repo.release_llm_deferred_alerts(limit=10, force=False)
            self.assertEqual(scheduled["released"], 0)
            self.assertEqual(repo.get_inbox_alert(alert.alert_id)["status"], "dead_letter")

            manual = repo.release_llm_deferred_alerts(limit=10, force=True)
            self.assertEqual(manual["released"], 1)
            self.assertEqual(manual["dead_letter_recovered"], 1)
            self.assertEqual(repo.get_inbox_alert(alert.alert_id)["status"], "retry")

    def test_terminal_llm_dead_letter_requires_manual_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            alert = _alert("terminal-llm-manual-recovery-001")
            repo.enqueue_alert(alert, max_attempts=12)
            repo.claim_inbox_alert(alert.alert_id)
            repo.dead_letter_inbox_alert(
                alert.alert_id,
                "LLMEndpointConfigurationError('LLM gateway rejected the request with HTTP 403')",
            )

            self.assertEqual(
                repo.release_llm_deferred_alerts(limit=10, force=False)["released"],
                0,
            )
            manual = repo.release_llm_deferred_alerts(limit=10, force=True)
            self.assertEqual(manual["released"], 1)
            self.assertEqual(manual["dead_letter_recovered"], 1)
            self.assertEqual(repo.get_inbox_alert(alert.alert_id)["status"], "retry")

    def test_due_deferred_alert_is_not_claimed_until_recovery_releases_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            alert = _alert("remote-deferred-dispatch-guard-001")
            repo.enqueue_alert(alert, max_attempts=3)
            self.assertIsNotNone(repo.claim_inbox_alert(alert.alert_id))
            self.assertTrue(
                repo.defer_inbox_alert(
                    alert.alert_id,
                    retry_delay_ms=0,
                    reason="remote LLM analysis deferred for durable retry",
                )
            )

            deferred = repo.get_inbox_alert(alert.alert_id)
            self.assertIsNotNone(deferred)
            self.assertEqual(deferred["status"], "deferred")
            self.assertEqual(deferred["attempts"], 0)
            # Even when the scheduled-recovery deadline is due, the normal
            # dispatcher cannot claim a remote-model deferral directly.
            self.assertIsNone(repo.claim_inbox_alert(alert.alert_id))

            released = repo.release_llm_deferred_alerts(limit=10, force=False)
            self.assertEqual(released["released"], 1)
            self.assertEqual(released["deferred_released"], 1)
            self.assertEqual(repo.get_inbox_alert(alert.alert_id)["status"], "retry")
            self.assertIsNotNone(repo.claim_inbox_alert(alert.alert_id))

    def test_local_rule_analyzer_cannot_release_remote_model_deferrals(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = True
            config.processing.workers = 1
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                unavailable = self._UnavailableRemoteLLM()
                state.llm = unavailable
                state.orchestrator.llm = unavailable
                alert = _alert("remote-deferred-local-guard-001")
                state.submit_alert(alert)
                self.assertTrue(
                    self._wait_until(
                        lambda: bool(
                            (record := state.repo.get_inbox_alert(alert.alert_id))
                            and record["status"] == "deferred"
                        )
                    )
                )

                local = LocalHeuristicLLM()
                state.llm = local
                state.orchestrator.llm = local
                blocked = state.release_llm_deferred_alerts(
                    limit=10,
                    actor="test-analyst",
                    force=True,
                )
                self.assertEqual(blocked["released"], 0)
                self.assertEqual(blocked["reason"], "remote_model_not_configured")
                self.assertFalse(state._llm_recovery_ready())
                self.assertEqual(state.repo.get_inbox_alert(alert.alert_id)["status"], "deferred")
                self.assertEqual(
                    state.repo.conn.execute("SELECT COUNT(*) FROM agent_runs").fetchone()[0],
                    0,
                )
            finally:
                state.stop()


class DurableInboxProductionControlTest(unittest.TestCase):
    def test_byte_capacity_is_released_when_work_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            first = _alert("byte-capacity-001")
            first.payload = {"body": "x" * 400}
            second = _alert("byte-capacity-002")
            second.payload = {"body": "y" * 400}

            self.assertEqual(
                repo.enqueue_alert_bounded(
                    first,
                    max_attempts=3,
                    capacity=10,
                    capacity_bytes=10_000,
                ),
                "inserted",
            )
            used = repo.inbox_capacity_stats()["unfinished_bytes"]
            self.assertGreater(used, 400)
            self.assertEqual(
                repo.enqueue_alert_bounded(
                    second,
                    max_attempts=3,
                    capacity=10,
                    capacity_bytes=used,
                ),
                "full",
            )
            repo.claim_inbox_alert(first.alert_id)
            repo.complete_inbox_alert(first.alert_id)
            self.assertEqual(repo.inbox_capacity_stats()["unfinished_bytes"], 0)
            self.assertEqual(
                repo.enqueue_alert_bounded(
                    second,
                    max_attempts=3,
                    capacity=10,
                    capacity_bytes=used,
                ),
                "inserted",
            )

    def test_dispatch_prefers_severity_then_rotating_product(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            low = _alert("dispatch-low-waf")
            low.severity = "low"
            critical = _alert("dispatch-critical-rasp")
            critical.product = "rasp"
            critical.severity = "critical"
            high_waf = _alert("dispatch-high-waf")
            high_waf.severity = "high"
            high_hips = _alert("dispatch-high-hips")
            high_hips.product = "hips"
            high_hips.severity = "high"
            for alert in (low, high_waf, high_hips, critical):
                repo.enqueue_alert(alert)

            claimed = repo.claim_inbox_alert(preferred_product="hips")
            self.assertEqual(claimed["alert_id"], critical.alert_id)
            repo.complete_inbox_alert(critical.alert_id)
            claimed = repo.claim_inbox_alert(preferred_product="hips")
            self.assertEqual(claimed["alert_id"], high_hips.alert_id)

    def test_claim_lease_can_be_renewed_and_execution_queue_is_worker_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = True
            config.processing.workers = 2
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                self.assertEqual(state.alert_processor.stats().queue_max_size, 2)
                alert = _alert("lease-renewal-001")
                state.repo.enqueue_alert(alert)
                claimed = state.repo.claim_inbox_alert(alert.alert_id)
                before = claimed["claimed_at_ms"]
                time.sleep(0.002)
                self.assertTrue(state.repo.renew_inbox_claim(alert.alert_id))
                self.assertGreaterEqual(
                    state.repo.get_inbox_alert(alert.alert_id)["claimed_at_ms"],
                    before,
                )
            finally:
                state.stop()

    def test_capacity_pauses_admission_without_removing_readiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = True
            config.processing.workers = 1
            config.processing.queue_max_size = 0
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                readiness = state.readiness()
                self.assertFalse(readiness["checks"]["inbox_capacity"]["ok"])
                self.assertTrue(readiness["ok"])
                with self.assertRaisesRegex(AlertQueueFull, "admission is paused"):
                    state.submit_alert(_alert("capacity-paused-001"))
            finally:
                state.stop()

    def test_inbox_list_supports_offset_and_total_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(str(Path(tmp) / "gateway.db"))
            for index in range(3):
                repo.enqueue_alert(_alert(f"page-{index}"))
            page = repo.list_inbox_alerts(limit=1, offset=1)
            self.assertEqual(len(page), 1)
            self.assertEqual(repo.count_inbox_alerts(), 3)


class LLMRuntimeRestoreTest(unittest.TestCase):
    def test_restart_retains_deployment_key_for_saved_allowed_gateway(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = str(Path(tmp) / "gateway.db")
            repo = Repository(database_path)
            repo.set_runtime_setting(
                "llm",
                {
                    "provider": "gateway",
                    "endpoint": "https://llm-gateway.example/analyze",
                    "model": "remote-test",
                    "timeout_seconds": 30,
                },
            )
            config = GatewayConfig()
            config.database.path = database_path
            config.llm.api_key = "deployment-secret"
            config.llm.allowed_hosts = ["llm-gateway.example"]
            config.processing.async_enabled = False
            config.syslog.embedded_listeners_enabled = False
            resolution = [(None, None, None, None, ("8.8.8.8", 443))]

            with patch("defensive_ai_gateway.app.socket.getaddrinfo", return_value=resolution):
                with patch("defensive_ai_gateway.llm.socket.getaddrinfo", return_value=resolution):
                    state = GatewayState(config)
            try:
                self.assertEqual(state.config.llm.provider, "gateway")
                self.assertEqual(state.config.llm.api_key, "deployment-secret")
                self.assertTrue(state.llm_config_payload()["api_key_set"])
            finally:
                state.stop()


class SyslogFrameDecoderTest(unittest.TestCase):
    def test_newline_frames_are_split_across_arbitrary_chunks(self):
        decoder = SyslogFrameDecoder(max_frame_bytes=64)
        self.assertEqual(decoder.feed(b"first\r"), [])
        self.assertEqual(decoder.feed(b"\nsecond\nthird"), [b"first", b"second"])
        self.assertEqual(decoder.finish(), [b"third"])

    def test_rfc6587_octet_counting_handles_multiple_partial_frames(self):
        decoder = SyslogFrameDecoder(max_frame_bytes=64)
        self.assertEqual(decoder.feed(b"3 on"), [])
        self.assertEqual(decoder.feed(b"e3 t"), [b"one"])
        self.assertEqual(decoder.feed(b"wo"), [b"two"])
        self.assertEqual(decoder.finish(), [])

    def test_pretty_printed_json_is_kept_as_one_frame(self):
        document = b'{\n  "event": {\n    "message": "brace } in string"\n  }\n}\n'
        decoder = SyslogFrameDecoder(max_frame_bytes=128)

        self.assertEqual(decoder.feed(document[:20]), [])
        self.assertEqual(decoder.feed(document[20:]), [document.strip()])
        self.assertEqual(decoder.finish(), [])

    def test_multiple_json_documents_are_still_dispatched_separately(self):
        decoder = SyslogFrameDecoder(max_frame_bytes=128)
        stream = b'{\n  "id": 1\n}\n{\n  "id": 2\n}\n'

        self.assertEqual(
            decoder.feed(stream),
            [b'{\n  "id": 1\n}', b'{\n  "id": 2\n}'],
        )

    def test_all_pretty_printed_demo_products_decode_as_single_frames(self):
        root = Path(__file__).resolve().parents[1] / "samples_syslog"
        for product in ("waf", "hips", "ndr", "rasp", "siem"):
            with self.subTest(product=product):
                document = (root / product / f"{product}_alert.json").read_bytes()
                decoder = SyslogFrameDecoder(max_frame_bytes=256 * 1024)
                self.assertEqual(decoder.feed(document), [document.strip()])
                self.assertEqual(decoder.finish(), [])

    def test_oversized_and_truncated_frames_are_rejected(self):
        with self.assertRaises(SyslogFrameError):
            SyslogFrameDecoder(max_frame_bytes=4).feed(b"5 hello")

        decoder = SyslogFrameDecoder(max_frame_bytes=8)
        decoder.feed(b"5 abc")
        with self.assertRaises(SyslogFrameError):
            decoder.finish()

    def test_json_frame_nesting_is_rejected_while_scanning(self):
        decoder = SyslogFrameDecoder(max_frame_bytes=4096)
        with self.assertRaisesRegex(SyslogFrameError, "nesting limit"):
            decoder.feed(b"{" * (MAX_JSON_NESTING + 1))

    def test_tcp_listener_dispatches_each_newline_frame_separately(self):
        received: list[bytes] = []
        listener = _SyslogListener(
            "127.0.0.1",
            SyslogListenerSpec("waf", 15140, "tcp"),
            lambda _spec, data, _peer: received.append(data),
            max_frame_bytes=64,
            max_connection_bytes=128,
        )
        server_sock, client_sock = socket.socketpair()
        thread = threading.Thread(
            target=listener._handle_tcp_connection,
            args=(server_sock, "local"),
            daemon=True,
        )
        thread.start()
        with client_sock:
            client_sock.sendall(b'{"id":1}\n{"id":2}\n')
            client_sock.shutdown(socket.SHUT_WR)
        thread.join(timeout=1)

        self.assertFalse(thread.is_alive())
        self.assertEqual(received, [b'{"id":1}', b'{"id":2}'])

    def test_tcp_listener_rejects_stream_over_connection_budget(self):
        received: list[bytes] = []
        listener = _SyslogListener(
            "127.0.0.1",
            SyslogListenerSpec("waf", 15140, "tcp"),
            lambda _spec, data, _peer: received.append(data),
            max_frame_bytes=8,
            max_connection_bytes=12,
        )
        server_sock, client_sock = socket.socketpair()
        thread = threading.Thread(
            target=listener._handle_tcp_connection,
            args=(server_sock, "local"),
            daemon=True,
        )
        thread.start()
        with client_sock:
            client_sock.sendall(b"one\ntwo\nthree\n")
            client_sock.shutdown(socket.SHUT_WR)
        thread.join(timeout=1)

        self.assertFalse(thread.is_alive())
        self.assertEqual(received, [])

    def test_manager_shares_one_global_connection_limit_across_listeners(self):
        manager = SyslogReceiverManager("127.0.0.1", lambda *_args: None, max_connections=1)
        first = manager._new_listener(SyslogListenerSpec("waf", 15140, "tcp"))
        second = manager._new_listener(SyslogListenerSpec("hips", 15141, "tcp"))

        self.assertIs(first._connection_slots, second._connection_slots)
        self.assertTrue(first._connection_slots.acquire(blocking=False))
        self.assertFalse(second._connection_slots.acquire(blocking=False))
        first._connection_slots.release()

    def test_listener_update_rolls_back_staged_changes_on_bind_failure(self):
        manager = SyslogReceiverManager("127.0.0.1", lambda *_args: None)
        class _FakeListener:
            def __init__(self, spec, fail=False):
                self.spec = spec
                self.fail = fail
                self.active = False

            def start(self):
                if self.fail:
                    raise OSError("simulated bind failure")
                self.active = True

            def stop(self):
                self.active = False

            def is_alive(self):
                return self.active

        def factory(spec):
            return _FakeListener(spec, fail=spec.product == "hips")

        with patch.object(manager, "_new_listener", side_effect=factory):
            manager.update([SyslogListenerSpec("waf", 15140, "tcp")])
            with self.assertRaises(OSError):
                manager.update(
                    [
                        SyslogListenerSpec("waf", 15140, "tcp"),
                        SyslogListenerSpec("hips", 15141, "tcp"),
                    ]
                )
        self.assertEqual(
            manager.status(),
            [
                {
                    "product": "waf",
                    "port": 15140,
                    "protocol": "tcp",
                    "active": True,
                }
            ],
        )
        manager.stop()

    def test_update_product_rejects_port_owned_by_another_product(self):
        manager = SyslogReceiverManager("127.0.0.1", lambda *_args: None)
        class _FakeListener:
            def __init__(self, spec):
                self.spec = spec
                self.active = False

            def start(self):
                self.active = True

            def stop(self):
                self.active = False

            def is_alive(self):
                return self.active

        with patch.object(manager, "_new_listener", side_effect=_FakeListener):
            manager.update([SyslogListenerSpec("waf", 15140, "tcp")])
            with self.assertRaisesRegex(OSError, "already assigned"):
                manager.update_product(SyslogListenerSpec("hips", 15140, "tcp"))
        self.assertEqual(manager.status()[0]["product"], "waf")
        manager.stop()


class SyslogDemoScriptTest(unittest.TestCase):
    def test_embedded_mode_reuses_running_listeners_and_waits_for_durable_completion(self):
        ports = {"waf": 15140, "hips": 15141, "ndr": 15142, "rasp": 15143, "siem": 15144}
        profiles = {product: f"auto-{product}-json" for product in ports}
        router = SyslogPortRouter(ports, profiles)
        samples = [
            (product, port, (ROOT / "samples_syslog" / product / f"{product}_alert.json").read_bytes())
            for product, port in ports.items()
        ]
        alert_products = {
            _embedded_expected_alert(router, product, port, data)[0]: product
            for product, port, data in samples
        }
        sent: list[bytes] = []

        class _FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def sendall(self, data: bytes) -> None:
                sent.append(data)

            def shutdown(self, _direction: int) -> None:
                return None

        def completed_inbox(url: str, **_kwargs) -> dict:
            alert_id = url.rsplit("/", 2)[-2]
            return {
                "status": 200,
                "body": {
                    "alert_id": alert_id,
                    "product": alert_products[alert_id],
                    "status": "completed",
                    "attempts": 1,
                    "last_error": "",
                },
            }

        with patch("scripts.simulate_syslog_ports.socket.create_connection", return_value=_FakeSocket()) as connect:
            with patch("scripts.simulate_syslog_ports._get_json", side_effect=completed_inbox):
                results = _send_to_embedded_listeners(
                    router,
                    samples,
                    "127.0.0.1",
                    "http://127.0.0.1:8080/api/alerts",
                    "",
                    1,
                )

        self.assertEqual(connect.call_count, 5)
        self.assertEqual(sent, [sample[2] for sample in samples])
        self.assertTrue(
            all(
                item["expected_product"] == item["routed_product"]
                and item["gateway_status"] == 200
                and item["inbox_status"] == "completed"
                for item in results
            )
        )


class SyslogEnvelopeTest(unittest.TestCase):
    def test_invalid_utf8_uses_persisted_text_hash_for_integrity(self):
        raw = b'{"trace_id":"invalid-\xff-utf8","severity":"high"}'
        routed = SyslogPortRouter({"waf": 15140}).route(
            15140,
            raw,
            protocol="tcp",
        )
        envelope = routed.envelope
        persisted = raw.decode("utf-8", errors="replace")
        persisted_hash = hashlib.sha256(persisted.encode("utf-8")).hexdigest()

        self.assertEqual(envelope["raw_message"], persisted)
        self.assertEqual(envelope["raw_message_bytes"], len(raw))
        self.assertEqual(
            envelope["raw_message_sha256"],
            hashlib.sha256(raw).hexdigest(),
        )
        self.assertEqual(envelope["raw_message_text_sha256"], persisted_hash)
        self.assertNotEqual(
            envelope["raw_message_sha256"],
            envelope["raw_message_text_sha256"],
        )

        descriptor = Repository._response_agent_syslog_descriptor(
            {"syslog_route": envelope}
        )
        self.assertEqual(descriptor["syslog_message_sha256"], persisted_hash)
        self.assertEqual(descriptor["syslog_recorded_sha256"], persisted_hash)
        self.assertEqual(descriptor["syslog_message_integrity"], "verified")

        tampered = dict(envelope)
        tampered["raw_message"] = persisted.replace("invalid", "changed")
        descriptor = Repository._response_agent_syslog_descriptor(
            {"syslog_route": tampered}
        )
        self.assertEqual(descriptor["syslog_message_integrity"], "mismatch")

    def test_legacy_syslog_hash_remains_compatible_for_valid_utf8(self):
        raw_message = '{"trace_id":"legacy-valid-utf8"}'
        descriptor = Repository._response_agent_syslog_descriptor(
            {
                "syslog_route": {
                    "raw_message": raw_message,
                    "raw_message_sha256": hashlib.sha256(
                        raw_message.encode("utf-8")
                    ).hexdigest(),
                }
            }
        )

        self.assertEqual(descriptor["syslog_message_integrity"], "verified")

    def test_legacy_lossy_utf8_is_unverified_instead_of_mismatched(self):
        raw = b'{"trace_id":"legacy-\xff-lossy"}'
        persisted = raw.decode("utf-8", errors="replace")
        descriptor = Repository._response_agent_syslog_descriptor(
            {
                "syslog_route": {
                    "raw_message": persisted,
                    "raw_message_bytes": len(raw),
                    "raw_message_sha256": hashlib.sha256(raw).hexdigest(),
                }
            }
        )

        self.assertEqual(descriptor["syslog_message_integrity"], "unverified")
        self.assertEqual(
            descriptor["syslog_message_integrity_reason"],
            "legacy_lossy_utf8",
        )

        tampered_text = '{"trace_id":"\ufffd-tampered"}'
        descriptor = Repository._response_agent_syslog_descriptor(
            {
                "syslog_route": {
                    "raw_message": tampered_text,
                    "raw_message_bytes": len(tampered_text.encode("utf-8")),
                    "raw_message_sha256": "0" * 64,
                }
            }
        )
        self.assertEqual(descriptor["syslog_message_integrity"], "mismatch")

    def test_router_rejects_excessive_json_structure(self):
        router = SyslogPortRouter({"waf": 15140})
        nested = "{}"
        for _ in range(MAX_JSON_NESTING + 1):
            nested = '{"nested":' + nested + "}"
        with self.assertRaisesRegex(ValueError, "nesting exceeds"):
            router.route(15140, nested)

        nodes = '{"items":[' + "0," * MAX_JSON_NODES + "0]}"
        with self.assertRaisesRegex(ValueError, "value count exceeds"):
            router.route(15140, nodes)

    def test_standard_route_preserves_transport_envelope_and_raw_message(self):
        raw = (
            b'<134>1 2026-07-14T10:00:00Z host waf - - - '
            b'{"alert_id":"waf-1","severity":"high",'
            b'"adapter":{"mapping_status":"passed"},'
            b'"mapped_entities":{"url":"FORGED-SYSLOG-URL"},'
            b'"collector_mapping_fallback":{"status":"forged"},'
            b'"Rasp_Evidence_Integrity":{"value":"CASE-VARIANT-SYSLOG-LEAK"}}'
        )
        router = SyslogPortRouter({"waf": 15140})
        routed = router.route(15140, raw, hostname="10.0.0.8", appname="waf", protocol="tcp")

        payload = routed.payload["payload"]
        envelope = payload["syslog_route"]
        self.assertEqual(envelope["destination_port"], 15140)
        self.assertEqual(envelope["hostname"], "10.0.0.8")
        self.assertEqual(envelope["protocol"], "tcp")
        self.assertEqual(envelope["route_reason"], "port_standard")
        self.assertEqual(envelope["raw_message"], raw.decode())
        self.assertEqual(envelope["raw_message_bytes"], len(raw))
        self.assertEqual(envelope["raw_message_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(envelope["message_format"], "embedded_json")
        self.assertNotIn("adapter", payload)
        self.assertNotIn("mapped_entities", payload)
        self.assertNotIn("collector_mapping_fallback", payload)
        self.assertNotIn("Rasp_Evidence_Integrity", payload)
        self.assertEqual(
            payload["original_log"]["mapped_entities"]["url"],
            "FORGED-SYSLOG-URL",
        )

        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                alert = state.alert_from_routed_syslog(routed)
                self.assertEqual(alert.payload["syslog_route"], routed.envelope)
                self.assertEqual(
                    alert.payload["original_log"]["mapped_entities"]["url"],
                    "FORGED-SYSLOG-URL",
                )
                rendered = json.dumps(
                    {
                        "entities": state.normalizer.normalize(alert).entities,
                        "evidence": state.normalizer.normalize(alert).evidence,
                    }
                )
                self.assertNotIn("FORGED-SYSLOG-URL", rendered)
                self.assertNotIn("CASE-VARIANT-SYSLOG-LEAK", rendered)

                vector_payload = json.loads(json.dumps(routed.payload))
                vector_route = dict(vector_payload["payload"]["syslog_route"])
                vector_route["collector"] = "vector"
                vector_payload["payload"]["syslog_route"] = vector_route
                validated_route = state.validated_http_collector_route(vector_payload)
                self.assertEqual(validated_route, vector_route)
                http_alert = state.alert_from_payload(
                    vector_payload,
                    trusted_syslog_route=validated_route,
                    trusted_original_log=state.collector_original_log(vector_payload),
                )
                self.assertEqual(http_alert.payload["syslog_route"], vector_route)
                self.assertEqual(
                    http_alert.payload["original_log"]["mapped_entities"]["url"],
                    "FORGED-SYSLOG-URL",
                )
            finally:
                state.stop()

    def test_adapter_rejects_excessive_nested_envelope_json(self):
        nested = "{}"
        for _ in range(MAX_JSON_NESTING + 1):
            nested = '{"nested":' + nested + "}"

        original = {"message": nested, "hostname": "collector-1"}
        decoded, envelope = LogAdapter().unwrap_syslog_envelope(original)

        self.assertEqual(decoded, original)
        self.assertIsNone(envelope)

    def test_profile_route_injects_envelope_into_mapped_log(self):
        router = SyslogPortRouter({"rasp": 15143}, {"rasp": "demo-rasp-json"})
        routed = router.route(
            15143,
            {"product": "rasp", "alert": {"id": "rasp-1"}},
            hostname="rasp-agent-1",
            appname="rasp",
            protocol="udp",
        )

        envelope = routed.payload["log"]["_syslog_envelope"]
        self.assertEqual(envelope["route_reason"], "port_profile")
        self.assertEqual(envelope["protocol"], "udp")
        self.assertEqual(routed.payload["syslog_route"], envelope)
        self.assertEqual(routed.envelope, envelope)

    def test_collector_profile_mapping_failure_is_preserved_with_raw_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = GatewayConfig()
            config.database.path = str(Path(tmp) / "gateway.db")
            config.processing.async_enabled = False
            config.syslog.embedded_listeners_enabled = False
            state = GatewayState(config)
            try:
                router = SyslogPortRouter(
                    {"rasp": 15143},
                    {"rasp": "auto-rasp-json"},
                )
                routed = router.route(
                    15143,
                    {
                        "data_type": "attack_event",
                        "event": {"app_name": "payment-api"},
                        "items": [{"rule_name": "command_execution"}],
                    },
                    hostname="rasp-agent-01",
                    appname="rasp",
                    protocol="tcp",
                )

                alert = state.alert_from_routed_syslog(routed)
                event = state.normalizer.normalize(alert)

                self.assertEqual(alert.product, "rasp")
                self.assertTrue(alert.alert_id.startswith("syslog_fallback_"))
                self.assertEqual(
                    alert.payload["collector_mapping_fallback"]["status"],
                    "accepted_with_mapping_error",
                )
                self.assertEqual(alert.payload["original_log"]["data_type"], "attack_event")
                self.assertEqual(alert.payload["syslog_route"]["route_reason"], "port_profile")
                self.assertIn(
                    "collector_mapping_fallback",
                    {item["type"] for item in event.evidence},
                )
                audit = state.repo.conn.execute(
                    "SELECT detail_json FROM audit_log WHERE action = 'collector_mapping_fallback'"
                ).fetchone()
                self.assertIsNotNone(audit)
                self.assertNotIn("original_log", audit["detail_json"])

                direct_payload = dict(routed.payload)
                direct_payload.pop("syslog_route")
                with self.assertRaisesRegex(ValueError, "log mapping failed"):
                    state.alert_from_payload(direct_payload, routed.profile_id)
            finally:
                state.stop()


class VectorCollectorManifestTest(unittest.TestCase):
    def test_collector_uses_persistent_backpressure_and_hardened_offline_runtime(self):
        manifest = (ROOT / "deploy" / "k3s" / "syslog-collector-vector.yaml").read_text(encoding="utf-8")

        self.assertIn("kind: PersistentVolumeClaim", manifest)
        self.assertIn('data_dir = "/var/lib/vector"', manifest)
        self.assertEqual(manifest.count('type = "disk"'), 2)
        self.assertEqual(manifest.count('when_full = "block"'), 2)
        self.assertIn("claimName: syslog-collector-vector-data", manifest)
        self.assertIn("imagePullPolicy: Never", manifest)
        self.assertIn("automountServiceAccountToken: false", manifest)
        self.assertIn("readOnlyRootFilesystem: true", manifest)
        self.assertIn("seccompProfile:", manifest)
        self.assertIn("readinessProbe:", manifest)
        self.assertIn("livenessProbe:", manifest)
        self.assertIn("structured._syslog_envelope = envelope", manifest)
        self.assertIn("payload.syslog_route = envelope", manifest)
        self.assertIn('[sources.syslog_rasp_udp]', manifest)
        self.assertIn('[sources.syslog_rasp_tcp]', manifest)
        self.assertGreaterEqual(manifest.count('max_length = 2_000_000'), 2)
        self.assertEqual(manifest.count("keepalive.time_secs = 60"), 5)
        self.assertIn("name: net.ipv4.tcp_keepalive_time", manifest)
        self.assertIn("name: net.ipv4.tcp_keepalive_intvl", manifest)
        self.assertIn("name: net.ipv4.tcp_keepalive_probes", manifest)
        self.assertIn('value: "15"', manifest)
        self.assertIn('value: "4"', manifest)
        self.assertIn('inputs = ["syslog_rasp_udp"]', manifest)
        self.assertIn('inputs = ["syslog_rasp_tcp"]', manifest)
        self.assertIn('"transport_assurance": to_string(.transport_assurance) ?? ""', manifest)
        self.assertIn('"protocol": to_string(.transport_protocol) ?? ""', manifest)
        self.assertIn("legacy_udp_best_effort", manifest)
        self.assertIn("name: rasp-udp", manifest)
        self.assertEqual(manifest.count("request.retry_attempts = 4294967295"), 2)
        self.assertEqual(manifest.count("request.retry_initial_backoff_secs = 1"), 2)


if __name__ == "__main__":
    unittest.main()
