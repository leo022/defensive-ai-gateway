"""Validated, DNS-pinned HTTP(S) transport helpers for model endpoints."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class EndpointPin:
    """A destination hostname bound to the safe addresses resolved for one request."""

    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower().rstrip(".")
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_prohibited_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def resolve_http_endpoint_pin(
    endpoint: str,
    *,
    backend: str,
    loopback_only: bool = False,
    allowed_hosts: list[str] | None = None,
    require_https_for_remote: bool = False,
    resolver: Callable[..., Any] | None = None,
) -> EndpointPin:
    """Validate an endpoint and retain the exact addresses for its connection.

    The returned pin is used by custom urllib handlers, so the later TCP
    connection cannot perform a second attacker-controlled DNS lookup.
    """
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{backend} endpoint must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError(f"{backend} endpoint must not contain user information")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"{backend} endpoint has an invalid port") from exc

    host = parsed.hostname.lower().rstrip(".")
    is_loopback = _is_loopback_host(host)
    if loopback_only and not is_loopback:
        raise ValueError(f"{backend} endpoint must use a loopback host")
    if require_https_for_remote and parsed.scheme != "https" and not is_loopback:
        raise ValueError("remote LLM gateway endpoints must use HTTPS")

    if not is_loopback and allowed_hosts is not None:
        allowed = {
            str(item).strip().lower().rstrip(".")
            for item in allowed_hosts
            if str(item).strip()
        }
        if host not in allowed:
            raise ValueError(f"{backend} host '{parsed.hostname}' is not allowlisted")

    resolve = resolver or socket.getaddrinfo
    try:
        resolved = resolve(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"{backend} endpoint cannot be resolved: {exc}") from exc

    addresses: list[str] = []
    for item in resolved:
        try:
            address_text = str(item[4][0])
            address = ipaddress.ip_address(address_text)
        except (IndexError, TypeError, ValueError) as exc:
            raise ValueError(f"{backend} endpoint returned an invalid address") from exc
        if is_loopback:
            if not address.is_loopback:
                raise ValueError(f"{backend} endpoint resolved outside loopback")
        elif _is_prohibited_address(address):
            raise ValueError(f"{backend} endpoint resolves to a disallowed network address")
        if address_text not in addresses:
            addresses.append(address_text)
    if not addresses:
        raise ValueError(f"{backend} endpoint did not resolve")
    return EndpointPin(parsed.scheme, host, port, tuple(addresses))


def _request_matches_pin(host: str, pin: EndpointPin) -> bool:
    try:
        parsed = urllib.parse.urlsplit(f"//{host}")
        request_host = (parsed.hostname or "").lower().rstrip(".")
        request_port = parsed.port or (443 if pin.scheme == "https" else 80)
    except ValueError:
        return False
    return request_host == pin.host and request_port == pin.port


def _connect_pinned_socket(
    pin: EndpointPin,
    timeout: Any,
    source_address: tuple[str, int] | None,
) -> socket.socket:
    """Connect only to addresses that were already validated for this request."""
    last_error: OSError | None = None
    for address in pin.addresses:
        parsed = ipaddress.ip_address(address)
        family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            try:
                sock.settimeout(timeout)
            except (TypeError, ValueError):
                pass
            if source_address:
                sock.bind(source_address)
            destination: tuple[Any, ...]
            if family == socket.AF_INET6:
                destination = (address, pin.port, 0, 0)
            else:
                destination = (address, pin.port)
            sock.connect(destination)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError("endpoint pin has no addresses")


def _configure_connected_socket(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, pin: EndpointPin, **kwargs: Any):
        if not _request_matches_pin(host, pin):
            raise OSError("request host does not match the validated endpoint")
        self._endpoint_pin = pin
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = _connect_pinned_socket(
            self._endpoint_pin, self.timeout, self.source_address
        )
        _configure_connected_socket(self.sock)
        if self._tunnel_host:
            self.sock.close()
            self.sock = None
            raise OSError("pinned endpoint transport does not support proxy tunnels")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, pin: EndpointPin, **kwargs: Any):
        if not _request_matches_pin(host, pin):
            raise OSError("request host does not match the validated endpoint")
        self._endpoint_pin = pin
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = _connect_pinned_socket(
            self._endpoint_pin, self.timeout, self.source_address
        )
        _configure_connected_socket(self.sock)
        if self._tunnel_host:
            self.sock.close()
            self.sock = None
            raise OSError("pinned endpoint transport does not support proxy tunnels")
        try:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
        except Exception:
            if self.sock is not None:
                self.sock.close()
            raise


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pin: EndpointPin):
        super().__init__()
        self._pin = pin

    def http_open(self, req: urllib.request.Request):
        return self.do_open(lambda host, **kwargs: _PinnedHTTPConnection(host, self._pin, **kwargs), req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pin: EndpointPin):
        super().__init__()
        self._pin = pin

    def https_open(self, req: urllib.request.Request):
        return self.do_open(lambda host, **kwargs: _PinnedHTTPSConnection(host, self._pin, **kwargs), req)


def pinned_endpoint_handlers(pin: EndpointPin) -> list[Any]:
    """Return the scheme-specific urllib handler that enforces an endpoint pin."""
    if pin.scheme == "https":
        return [_PinnedHTTPSHandler(pin)]
    return [_PinnedHTTPHandler(pin)]
