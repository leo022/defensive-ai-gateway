from __future__ import annotations

# ruff: noqa: E402 -- source checkout scripts add the project root before imports.

import argparse
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defensive_ai_gateway.config import load_config
from defensive_ai_gateway.log_adapter import LogAdapter, builtin_product_profile
from defensive_ai_gateway.syslog_router import SyslogPortRouter


def _post_json(url: str, payload: dict, token: str, timeout: int = 10) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {"status": resp.status, "body": json.loads(resp.read().decode("utf-8"))}


def _get_json(url: str, token: str = "", timeout: int = 5) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": resp.status, "body": json.loads(resp.read().decode("utf-8"))}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"error": body}
        return {"status": exc.code, "body": parsed}


def _embedded_expected_alert(router: SyslogPortRouter, product: str, port: int, data: bytes) -> tuple[str, str]:
    routed = router.route(port, data, hostname="127.0.0.1", appname=product, protocol="tcp")
    log = routed.payload.get("log")
    if not isinstance(log, dict):
        raise ValueError(f"{product} sample did not route through a mapping profile")
    adapted = LogAdapter().adapt(builtin_product_profile(product), log)
    alert = adapted.get("raw_alert")
    if alert is None:
        raise ValueError(f"{product} sample mapping failed: {adapted.get('errors', [])}")
    return alert.alert_id, routed.profile_id


def _send_to_embedded_listeners(
    router: SyslogPortRouter,
    samples: list[tuple[str, int, bytes]],
    host: str,
    gateway_url: str,
    token: str,
    timeout: float,
) -> list[dict]:
    results: list[dict] = []
    for product, port, data in samples:
        try:
            alert_id, profile_id = _embedded_expected_alert(router, product, port, data)
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.sendall(data)
                sock.shutdown(socket.SHUT_WR)
            results.append(
                {
                    "port": port,
                    "expected_product": product,
                    "alert_id": alert_id,
                    "profile_id": profile_id,
                    "route_reason": "embedded_listener",
                }
            )
        except Exception as exc:  # noqa: BLE001 - included in the simulator report
            results.append({"port": port, "expected_product": product, "error": str(exc)})

    deadline = time.time() + timeout
    while time.time() < deadline:
        pending = [item for item in results if item.get("alert_id") and item.get("inbox_status") != "completed"]
        if not pending:
            break
        for item in pending:
            alert_id = quote(str(item["alert_id"]), safe="")
            response = _get_json(f"{gateway_url.rstrip('/')}/{alert_id}/inbox", token=token)
            item["gateway_status"] = response["status"]
            body = response.get("body") or {}
            if response["status"] == 200:
                item["routed_product"] = body.get("product")
                item["inbox_status"] = body.get("status")
                item["attempts"] = body.get("attempts")
                item["last_error"] = body.get("last_error")
        if any(item.get("inbox_status") != "completed" for item in pending):
            time.sleep(0.05)
    return results


class TcpCollectorSimulator:
    def __init__(self, host: str, router: SyslogPortRouter, gateway_url: str, token: str = ""):
        self.host = host
        self.router = router
        self.gateway_url = gateway_url
        self.token = token
        self.results: list[dict] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for product, port in sorted(self.router.product_ports.items(), key=lambda item: item[1]):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, int(port)))
            sock.listen(16)
            sock.settimeout(0.2)
            self._sockets.append(sock)
            thread = threading.Thread(target=self._serve_socket, args=(sock, product, int(port)), daemon=True)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        for sock in self._sockets:
            sock.close()
        for thread in self._threads:
            thread.join(timeout=1)

    def _serve_socket(self, sock: socket.socket, product: str, port: int) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                chunks: list[bytes] = []
                with conn:
                    conn.settimeout(1)
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                data = b"".join(chunks)
                routed = self.router.route(port, data, hostname=addr[0], appname=product)
                response = _post_json(self.gateway_url, routed.payload, self.token)
                record = {
                    "port": port,
                    "expected_product": product,
                    "routed_product": routed.product,
                    "profile_id": routed.profile_id,
                    "route_reason": routed.route_reason,
                    "warnings": routed.warnings,
                    "gateway_status": response["status"],
                    "gateway_body": response["body"],
                }
            except Exception as exc:  # noqa: BLE001 - printed in the simulator report
                record = {"port": port, "expected_product": product, "error": str(exc)}
            with self._lock:
                self.results.append(record)

    def wait_for_results(self, count: int, timeout: float) -> list[dict]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if len(self.results) >= count:
                    return list(self.results)
            time.sleep(0.05)
        with self._lock:
            return list(self.results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate different security devices sending syslog to product-specific TCP ports.")
    parser.add_argument("--config", default="config/dev.yaml")
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8080/api/alerts")
    parser.add_argument("--health-url", default="http://127.0.0.1:8080/api/health")
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--token", default=os.getenv("DEFENSIVE_AI_API_TOKEN", ""))
    args = parser.parse_args()

    config = load_config(args.config)
    health = _get_json(args.health_url, token=args.token)
    if health["status"] != 200 or not health["body"].get("ok"):
        raise SystemExit(f"gateway health check failed: {health}")

    router = SyslogPortRouter(config.syslog.product_ports, config.syslog.gateway_profiles)
    samples: list[tuple[str, int, bytes]] = []
    for product, port in sorted(config.syslog.product_ports.items(), key=lambda item: item[1]):
        sample_path = PROJECT_ROOT / "samples_syslog" / product / f"{product}_alert.json"
        samples.append((product, int(port), sample_path.read_bytes()))

    if config.syslog.embedded_listeners_enabled:
        results = _send_to_embedded_listeners(
            router,
            samples,
            args.bind_host,
            args.gateway_url,
            args.token,
            args.timeout,
        )
    else:
        collector = TcpCollectorSimulator(args.bind_host, router, args.gateway_url, args.token)
        collector.start()
        try:
            for product, port, data in samples:
                with socket.create_connection((args.bind_host, port), timeout=args.timeout) as sock:
                    sock.sendall(data)
            results = collector.wait_for_results(len(samples), args.timeout)
        finally:
            collector.stop()

    ok = len(results) == len(samples) and all(
        item.get("expected_product") == item.get("routed_product")
        and (
            item.get("gateway_status") == 202
            or (item.get("gateway_status") == 200 and item.get("inbox_status") == "completed")
        )
        for item in results
    )
    print(json.dumps({"ok": ok, "health": health["body"], "results": results}, ensure_ascii=False, indent=2))
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
