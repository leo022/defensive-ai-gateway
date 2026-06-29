from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080


@dataclass
class DatabaseConfig:
    path: str = "data/gateway.db"


@dataclass
class LLMConfig:
    provider: str = "local"
    endpoint: str = ""
    api_key_env: str = "DEFENSIVE_AI_LLM_API_KEY"
    api_key: str = ""
    model: str = "local-rule-analyst"
    timeout_seconds: int = 30


@dataclass
class PolicyConfig:
    mode: str = "read_only"
    max_prompt_chars: int = 12000
    max_context_bytes: int = 20000
    require_approval_for: list[str] = field(default_factory=lambda: ["block", "isolate", "change_policy", "disable_account"])
    redact_fields: list[str] = field(
        default_factory=lambda: [
            "password",
            "token",
            "cookie",
            "authorization",
            "customer_id",
            "id_card",
            "phone",
            "email",
            "session",
        ]
    )


@dataclass
class AuthConfig:
    """HTTP API authentication.

    For a banking SOC gateway every mutating endpoint (and the LLM config
    endpoints) must be authenticated. The lightest stdlib-only mechanism is a
    shared bearer token read from the environment. When no token is configured
    the gateway falls back to loopback-only access so local dev/tests stay
    usable; production must set ``api_token`` and front the service with mTLS /
    a reverse proxy (see deploy/k3s).
    """
    api_token: str = ""
    # When True (default), requests originating from 127.0.0.1/::1 are accepted
    # even without a token — keeps local dev and the test harness working.
    allow_loopback_no_token: bool = True
    # When True, an unauthenticated non-loopback request with no token
    # configured is rejected (fail-closed for network-exposed deployments).
    require_token_when_remote: bool = True


@dataclass
class GatewayConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value.startswith("[") and value.endswith("]"):
        raw = value[1:-1].strip()
        if not raw:
            return []
        return [part.strip().strip("'\"") for part in raw.split(",")]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        return value


def parse_simple_yaml(path: Path) -> dict[str, Any]:
    """Parse the small YAML subset used by this project.

    This avoids a hard PyYAML dependency for air-gapped migration. Supported
    syntax: nested maps by indentation, scalars, and one-line lists.
    """
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        key, sep, value = line.strip().partition(":")
        if not sep:
            raise ValueError(f"Invalid config line: {raw_line}")
        while stack and indent <= stack[-1][0]:
            stack.pop()
        current = stack[-1][1]
        if value.strip() == "":
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent, child))
        else:
            current[key] = _parse_scalar(value)
    return root


def load_config(path: str | None = None) -> GatewayConfig:
    raw: dict[str, Any] = {}
    if path:
        raw = parse_simple_yaml(Path(path))

    server = raw.get("server", {})
    database = raw.get("database", {})
    llm = raw.get("llm", {})
    policy = raw.get("policy", {})
    auth = raw.get("auth", {})
    api_key_env = str(llm.get("api_key_env", "DEFENSIVE_AI_LLM_API_KEY"))

    config = GatewayConfig(
        server=ServerConfig(
            host=str(os.getenv("DEFENSIVE_AI_HOST", server.get("host", "127.0.0.1"))),
            port=int(os.getenv("DEFENSIVE_AI_PORT", server.get("port", 8080))),
        ),
        database=DatabaseConfig(path=str(os.getenv("DEFENSIVE_AI_DB", database.get("path", "data/gateway.db")))),
        llm=LLMConfig(
            provider=str(os.getenv("DEFENSIVE_AI_LLM_PROVIDER", llm.get("provider", "local"))),
            endpoint=str(os.getenv("DEFENSIVE_AI_LLM_ENDPOINT", llm.get("endpoint", ""))),
            api_key_env=api_key_env,
            api_key=str(os.getenv(api_key_env, llm.get("api_key", ""))),
            model=str(llm.get("model", "local-rule-analyst")),
            timeout_seconds=int(llm.get("timeout_seconds", 30)),
        ),
        policy=PolicyConfig(
            mode=str(policy.get("mode", "read_only")),
            max_prompt_chars=int(policy.get("max_prompt_chars", 12000)),
            max_context_bytes=int(policy.get("max_context_bytes", 20000)),
            require_approval_for=list(policy.get("require_approval_for", ["block", "isolate", "change_policy", "disable_account"])),
            redact_fields=list(
                policy.get(
                    "redact_fields",
                    ["password", "token", "cookie", "authorization", "customer_id", "id_card", "phone", "email", "session"],
                )
            ),
        ),
        auth=AuthConfig(
            api_token=str(os.getenv("DEFENSIVE_AI_API_TOKEN", auth.get("api_token", ""))),
            allow_loopback_no_token=str(
                os.getenv("DEFENSIVE_AI_AUTH_LOOPBACK", "1" if auth.get("allow_loopback_no_token", True) else "0")
            )
            in {"1", "true", "True", "yes"},
            require_token_when_remote=str(
                os.getenv("DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN", "1" if auth.get("require_token_when_remote", True) else "0")
            )
            in {"1", "true", "True", "yes"},
        ),
    )
    return config
