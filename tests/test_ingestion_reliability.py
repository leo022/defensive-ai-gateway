from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from defensive_ai_gateway.app import GatewayState
from defensive_ai_gateway.config import GatewayConfig
from defensive_ai_gateway.json_safety import MAX_JSON_NESTING, MAX_JSON_NODES
from defensive_ai_gateway.models import RawAlert
from defensive_ai_gateway.processing import AlertProcessor, DeadLetter
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
        raw = b'<134>1 2026-07-14T10:00:00Z host waf - - - {"alert_id":"waf-1","severity":"high"}'
        router = SyslogPortRouter({"waf": 15140})
        routed = router.route(15140, raw, hostname="10.0.0.8", appname="waf", protocol="tcp")

        envelope = routed.payload["payload"]["syslog_route"]
        self.assertEqual(envelope["destination_port"], 15140)
        self.assertEqual(envelope["hostname"], "10.0.0.8")
        self.assertEqual(envelope["protocol"], "tcp")
        self.assertEqual(envelope["route_reason"], "port_standard")
        self.assertEqual(envelope["raw_message"], raw.decode())
        self.assertEqual(envelope["message_format"], "embedded_json")

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


if __name__ == "__main__":
    unittest.main()
