from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class SyslogListenerSpec:
    product: str
    port: int
    protocol: str


class _SyslogListener:
    def __init__(self, host: str, spec: SyslogListenerSpec, on_message: Callable[[SyslogListenerSpec, bytes, str], None]):
        self.host = host
        self.spec = spec
        self.on_message = on_message
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        sock_type = socket.SOCK_STREAM if self.spec.protocol == "tcp" else socket.SOCK_DGRAM
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.host, self.spec.port))
            if self.spec.protocol == "tcp":
                sock.listen(32)
            sock.settimeout(0.2)
        except Exception:
            sock.close()
            raise
        self._socket = sock
        target = self._serve_tcp if self.spec.protocol == "tcp" else self._serve_udp
        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._socket:
            self._socket.close()
        if self._thread:
            self._thread.join(timeout=1)

    def _serve_udp(self) -> None:
        sock = self._socket
        if not sock:
            return
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self._handle(data, addr[0] if addr else "")

    def _serve_tcp(self) -> None:
        sock = self._socket
        if not sock:
            return
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle_tcp_connection, args=(conn, addr[0] if addr else ""), daemon=True).start()

    def _handle_tcp_connection(self, conn: socket.socket, peer: str) -> None:
        chunks: list[bytes] = []
        with conn:
            conn.settimeout(2)
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                except OSError:
                    return
                if not chunk:
                    break
                chunks.append(chunk)
        self._handle(b"".join(chunks), peer)

    def _handle(self, data: bytes, peer: str) -> None:
        if not data:
            return
        try:
            self.on_message(self.spec, data, peer)
        except Exception as exc:  # noqa: BLE001 - runtime receiver must keep accepting logs
            print(f"[syslog] failed to process {self.spec.protocol}/{self.spec.port} {self.spec.product}: {exc!r}")


class SyslogReceiverManager:
    def __init__(self, host: str, on_message: Callable[[SyslogListenerSpec, bytes, str], None]):
        self.host = host
        self.on_message = on_message
        self._lock = threading.RLock()
        self._listeners: dict[tuple[str, int], _SyslogListener] = {}

    def update(self, specs: list[SyslogListenerSpec]) -> list[dict]:
        desired = {(spec.protocol, spec.port): spec for spec in specs}
        with self._lock:
            for key in list(self._listeners):
                current = self._listeners[key].spec
                wanted = desired.get(key)
                if not wanted or wanted.product != current.product:
                    self._listeners.pop(key).stop()

            for key, spec in desired.items():
                if key in self._listeners:
                    continue
                listener = _SyslogListener(self.host, spec, self.on_message)
                try:
                    listener.start()
                except Exception as exc:
                    raise OSError(f"failed to bind syslog {spec.protocol.upper()} {spec.port} for {spec.product}: {exc}") from exc
                self._listeners[key] = listener
            return self.status()

    def update_product(self, spec: SyslogListenerSpec) -> list[dict]:
        key = (spec.protocol, spec.port)
        with self._lock:
            if key not in self._listeners:
                listener = _SyslogListener(self.host, spec, self.on_message)
                try:
                    listener.start()
                except Exception as exc:
                    raise OSError(f"failed to bind syslog {spec.protocol.upper()} {spec.port} for {spec.product}: {exc}") from exc
                self._listeners[key] = listener
            for current_key in list(self._listeners):
                current = self._listeners[current_key].spec
                if current.product == spec.product and current_key != key:
                    self._listeners.pop(current_key).stop()
            return self.status()

    def status(self) -> list[dict]:
        with self._lock:
            return [
                {"product": listener.spec.product, "port": listener.spec.port, "protocol": listener.spec.protocol, "active": True}
                for listener in sorted(self._listeners.values(), key=lambda item: (item.spec.port, item.spec.protocol))
            ]

    def stop(self) -> None:
        with self._lock:
            listeners = list(self._listeners.values())
            self._listeners.clear()
        for listener in listeners:
            listener.stop()
