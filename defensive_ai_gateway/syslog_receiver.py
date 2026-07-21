from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from .json_safety import MAX_JSON_NESTING


@dataclass(frozen=True)
class SyslogListenerSpec:
    product: str
    port: int
    protocol: str


class SyslogFrameError(ValueError):
    """Raised when a TCP syslog stream violates framing or size limits."""


class SyslogFrameDecoder:
    """Incrementally decode RFC6587 octet-counted or newline-delimited frames.

    A final non-delimited frame is accepted on EOF/idle timeout for compatibility
    with simple devices and the local demo sender, which send one JSON document
    and close the connection without appending a newline.
    """

    _MAX_LENGTH_DIGITS = 10

    def __init__(self, max_frame_bytes: int):
        self.max_frame_bytes = max(1, int(max_frame_bytes))
        self._buffer = bytearray()
        self._expected_octets: int | None = None

    def feed(self, chunk: bytes) -> list[bytes]:
        if chunk:
            self._buffer.extend(chunk)
        frames: list[bytes] = []
        while self._buffer:
            if self._expected_octets is not None:
                if len(self._buffer) < self._expected_octets:
                    break
                size = self._expected_octets
                frame = bytes(self._buffer[:size])
                del self._buffer[:size]
                self._expected_octets = None
                if frame:
                    frames.append(frame)
                continue

            prefix_state = self._consume_octet_prefix()
            if prefix_state == "consumed":
                if self._expected_octets == 0:
                    self._expected_octets = None
                continue
            if prefix_state == "wait":
                break

            json_state, json_frame = self._consume_json_document()
            if json_state == "consumed":
                if json_frame:
                    frames.append(json_frame)
                continue
            if json_state == "wait":
                break

            newline = self._buffer.find(b"\n")
            if newline < 0:
                if len(self._buffer) > self.max_frame_bytes:
                    raise SyslogFrameError(f"newline-delimited syslog frame exceeds {self.max_frame_bytes} bytes")
                break
            frame = bytes(self._buffer[:newline]).removesuffix(b"\r")
            del self._buffer[: newline + 1]
            if len(frame) > self.max_frame_bytes:
                raise SyslogFrameError(f"newline-delimited syslog frame exceeds {self.max_frame_bytes} bytes")
            if frame:
                frames.append(frame)
        return frames

    def _consume_json_document(self) -> tuple[str, bytes | None]:
        """Keep a pretty-printed JSON document intact in a newline stream."""
        start = 0
        while start < len(self._buffer) and self._buffer[start] in b" \t\r\n":
            start += 1
        if start >= len(self._buffer) or self._buffer[start] not in (ord("{"), ord("[")):
            return "not_json", None

        stack: list[int] = []
        in_string = False
        escaped = False
        for index in range(start, len(self._buffer)):
            byte = self._buffer[index]
            if in_string:
                if escaped:
                    escaped = False
                elif byte == ord("\\"):
                    escaped = True
                elif byte == ord('"'):
                    in_string = False
                continue
            if byte == ord('"'):
                in_string = True
            elif byte in (ord("{"), ord("[")):
                stack.append(byte)
                if len(stack) > MAX_JSON_NESTING:
                    raise SyslogFrameError("JSON syslog frame exceeds the nesting limit")
            elif byte in (ord("}"), ord("]")):
                expected = ord("{") if byte == ord("}") else ord("[")
                if not stack or stack[-1] != expected:
                    return "not_json", None
                stack.pop()
                if not stack:
                    frame = bytes(self._buffer[start : index + 1])
                    del self._buffer[: index + 1]
                    while self._buffer and self._buffer[0] in b" \t\r\n":
                        del self._buffer[0]
                    if len(frame) > self.max_frame_bytes:
                        raise SyslogFrameError(f"JSON syslog frame exceeds {self.max_frame_bytes} bytes")
                    return "consumed", frame

        if len(self._buffer) - start > self.max_frame_bytes:
            raise SyslogFrameError(f"JSON syslog frame exceeds {self.max_frame_bytes} bytes")
        return "wait", None

    def finish(self) -> list[bytes]:
        """Flush a compatibility frame at EOF, rejecting truncated RFC6587."""
        frames = self.feed(b"")
        if self._expected_octets is not None:
            raise SyslogFrameError(
                f"truncated RFC6587 frame: expected {self._expected_octets} bytes, received {len(self._buffer)}"
            )
        if not self._buffer:
            return frames
        if len(self._buffer) > self.max_frame_bytes:
            raise SyslogFrameError(f"syslog frame exceeds {self.max_frame_bytes} bytes")
        frame = bytes(self._buffer).removesuffix(b"\r")
        self._buffer.clear()
        if frame:
            frames.append(frame)
        return frames

    def _consume_octet_prefix(self) -> str:
        if not self._buffer or not 48 <= self._buffer[0] <= 57:
            return "not_octet"
        space = self._buffer.find(b" ")
        newline = self._buffer.find(b"\n")
        if newline >= 0 and (space < 0 or newline < space):
            return "not_octet"
        if space < 0:
            if all(48 <= byte <= 57 for byte in self._buffer):
                if len(self._buffer) > self._MAX_LENGTH_DIGITS:
                    raise SyslogFrameError("RFC6587 length prefix is too long")
                return "wait"
            return "not_octet"
        prefix = bytes(self._buffer[:space])
        if not prefix.isdigit():
            return "not_octet"
        if len(prefix) > self._MAX_LENGTH_DIGITS:
            raise SyslogFrameError("RFC6587 length prefix is too long")
        size = int(prefix)
        if size > self.max_frame_bytes:
            raise SyslogFrameError(f"RFC6587 syslog frame exceeds {self.max_frame_bytes} bytes")
        del self._buffer[: space + 1]
        self._expected_octets = size
        return "consumed"


class _SyslogListener:
    def __init__(
        self,
        host: str,
        spec: SyslogListenerSpec,
        on_message: Callable[[SyslogListenerSpec, bytes, str], None],
        *,
        max_frame_bytes: int = 256 * 1024,
        max_connection_bytes: int = 4 * 1024 * 1024,
        tcp_idle_timeout: float = 2.0,
        connection_slots: threading.BoundedSemaphore | None = None,
    ):
        self.host = host
        self.spec = spec
        self.on_message = on_message
        self.max_frame_bytes = max(1, int(max_frame_bytes))
        self.max_connection_bytes = max(self.max_frame_bytes, int(max_connection_bytes))
        self.tcp_idle_timeout = max(0.1, float(tcp_idle_timeout))
        self._connection_slots = connection_slots or threading.BoundedSemaphore(128)
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._connections_lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._connection_threads: set[threading.Thread] = set()

    def start(self) -> None:
        if self.spec.protocol not in {"tcp", "udp"}:
            raise ValueError(f"unsupported syslog protocol: {self.spec.protocol}")
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
        self._thread = threading.Thread(
            target=target,
            name=f"syslog-{self.spec.product}-{self.spec.protocol}-{self.spec.port}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._socket:
            self._socket.close()
        with self._connections_lock:
            connections = list(self._connections)
            threads = list(self._connection_threads)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        current_thread = threading.current_thread()
        if self._thread:
            self._thread.join(timeout=1)
        # Use one shared deadline so many idle clients cannot extend shutdown
        # by one timeout each.
        stop_deadline = time.monotonic() + 1
        for thread in threads:
            if thread is current_thread:
                continue
            thread.join(timeout=max(0, stop_deadline - time.monotonic()))

    def is_alive(self) -> bool:
        return bool(
            not self._stop.is_set()
            and self._socket is not None
            and self._thread is not None
            and self._thread.is_alive()
        )

    def _serve_udp(self) -> None:
        sock = self._socket
        if not sock:
            return
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(min(65535, self.max_frame_bytes + 1))
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) > self.max_frame_bytes:
                print(
                    f"[syslog] dropped oversized UDP frame on {self.spec.port}: "
                    f"{len(data)} > {self.max_frame_bytes} bytes"
                )
                continue
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
            if self._stop.is_set():
                conn.close()
                return
            if not self._connection_slots.acquire(blocking=False):
                conn.close()
                print(f"[syslog] rejected TCP connection on {self.spec.port}: concurrency limit reached")
                continue
            peer = addr[0] if addr else ""
            thread = threading.Thread(
                target=self._connection_entry,
                args=(conn, peer),
                name=f"syslog-client-{self.spec.product}-{peer or 'unknown'}",
                daemon=True,
            )
            with self._connections_lock:
                self._connections.add(conn)
                self._connection_threads.add(thread)
            try:
                thread.start()
            except Exception:
                with self._connections_lock:
                    self._connections.discard(conn)
                    self._connection_threads.discard(thread)
                self._connection_slots.release()
                conn.close()
                raise

    def _connection_entry(self, conn: socket.socket, peer: str) -> None:
        try:
            self._handle_tcp_connection(conn, peer)
        finally:
            with self._connections_lock:
                self._connections.discard(conn)
                self._connection_threads.discard(threading.current_thread())
            self._connection_slots.release()

    def _handle_tcp_connection(self, conn: socket.socket, peer: str) -> None:
        decoder = SyslogFrameDecoder(self.max_frame_bytes)
        connection_bytes = 0
        with conn:
            conn.settimeout(self.tcp_idle_timeout)
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                except OSError:
                    return
                if not chunk:
                    break
                connection_bytes += len(chunk)
                if connection_bytes > self.max_connection_bytes:
                    print(
                        f"[syslog] dropped TCP connection on {self.spec.port}: "
                        f"stream exceeds {self.max_connection_bytes} bytes"
                    )
                    return
                try:
                    frames = decoder.feed(chunk)
                except SyslogFrameError as exc:
                    print(f"[syslog] dropped malformed TCP stream on {self.spec.port}: {exc}")
                    return
                for frame in frames:
                    self._handle(frame, peer)
            try:
                frames = decoder.finish()
            except SyslogFrameError as exc:
                print(f"[syslog] dropped incomplete TCP stream on {self.spec.port}: {exc}")
                return
            for frame in frames:
                self._handle(frame, peer)

    def _handle(self, data: bytes, peer: str) -> None:
        if not data:
            return
        try:
            self.on_message(self.spec, data, peer)
        except Exception as exc:  # noqa: BLE001 - runtime receiver must keep accepting logs
            print(f"[syslog] failed to process {self.spec.protocol}/{self.spec.port} {self.spec.product}: {exc!r}")


class SyslogReceiverManager:
    def __init__(
        self,
        host: str,
        on_message: Callable[[SyslogListenerSpec, bytes, str], None],
        *,
        max_frame_bytes: int = 256 * 1024,
        max_connection_bytes: int = 4 * 1024 * 1024,
        max_connections: int = 128,
        tcp_idle_timeout: float = 2.0,
    ):
        self.host = host
        self.on_message = on_message
        self.max_frame_bytes = max(1, int(max_frame_bytes))
        self.max_connection_bytes = max(self.max_frame_bytes, int(max_connection_bytes))
        self.max_connections = max(1, int(max_connections))
        self.tcp_idle_timeout = max(0.1, float(tcp_idle_timeout))
        self._connection_slots = threading.BoundedSemaphore(self.max_connections)
        self._lock = threading.RLock()
        self._listeners: dict[tuple[str, int], _SyslogListener] = {}

    def update(self, specs: list[SyslogListenerSpec]) -> list[dict]:
        desired = {(spec.protocol, spec.port): spec for spec in specs}
        with self._lock:
            # Stage every new socket first. If any bind fails, stop only the
            # staged listeners and leave the previously working set untouched.
            staged: dict[tuple[str, int], _SyslogListener] = {}
            try:
                for key, spec in desired.items():
                    if key in self._listeners:
                        continue
                    listener = self._new_listener(spec)
                    listener.start()
                    staged[key] = listener
            except Exception as exc:
                for listener in staged.values():
                    listener.stop()
                raise OSError(
                    f"failed to bind syslog {spec.protocol.upper()} {spec.port} "
                    f"for {spec.product}: {exc}"
                ) from exc

            for key in list(self._listeners):
                if key not in desired:
                    self._listeners.pop(key).stop()
            for key, wanted in desired.items():
                if key in self._listeners:
                    # A product-label change does not require rebinding the same
                    # socket and therefore cannot create a partial outage.
                    self._listeners[key].spec = wanted
            self._listeners.update(staged)
            return self.status()

    def update_product(self, spec: SyslogListenerSpec) -> list[dict]:
        key = (spec.protocol, spec.port)
        with self._lock:
            occupied = self._listeners.get(key)
            if occupied and occupied.spec.product != spec.product:
                raise OSError(
                    f"syslog {spec.protocol.upper()} {spec.port} is already assigned "
                    f"to {occupied.spec.product}"
                )
            if key not in self._listeners:
                listener = self._new_listener(spec)
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
                {
                    "product": listener.spec.product,
                    "port": listener.spec.port,
                    "protocol": listener.spec.protocol,
                    "active": listener.is_alive(),
                }
                for listener in sorted(self._listeners.values(), key=lambda item: (item.spec.port, item.spec.protocol))
            ]

    def stop(self) -> None:
        with self._lock:
            listeners = list(self._listeners.values())
            self._listeners.clear()
        for listener in listeners:
            listener.stop()

    def _new_listener(self, spec: SyslogListenerSpec) -> _SyslogListener:
        return _SyslogListener(
            self.host,
            spec,
            self.on_message,
            max_frame_bytes=self.max_frame_bytes,
            max_connection_bytes=self.max_connection_bytes,
            tcp_idle_timeout=self.tcp_idle_timeout,
            connection_slots=self._connection_slots,
        )
