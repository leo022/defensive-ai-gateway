from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    max_connections: int = 128
    read_timeout_seconds: int = 15
    requests_per_minute: int = 6000


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
    allowed_hosts: list[str] = field(default_factory=list)
    max_response_bytes: int = 2_000_000
    max_retries: int = 1


@dataclass
class PolicyConfig:
    mode: str = "read_only"
    max_prompt_chars: int = 12000
    max_context_bytes: int = 20000
    approval_quorum: int = 1
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
class AuthPrincipalConfig:
    actor: str
    token: str
    roles: list[str] = field(default_factory=list)


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
    ingest_token: str = ""
    operator_token: str = ""
    approver_token: str = ""
    # When True (default), requests originating from 127.0.0.1/::1 are accepted
    # even without a token — keeps local dev and the test harness working.
    allow_loopback_no_token: bool = True
    # When True, an unauthenticated non-loopback request with no token
    # configured is rejected (fail-closed for network-exposed deployments).
    require_token_when_remote: bool = True
    # Explicit escape hatch for isolated workshops/container demos. Production
    # manifests must keep this false; merely disabling remote-token enforcement
    # is not sufficient to enable an unauthenticated network service.
    demo_mode: bool = False
    # Optional named identities allow quorum votes to represent real distinct
    # operators instead of another shared role token. Tokens should normally be
    # supplied through each entry's token_env setting.
    principals: list[AuthPrincipalConfig] = field(default_factory=list)


@dataclass
class ProcessingConfig:
    """Inbound alert processing backpressure controls."""

    async_enabled: bool = True
    queue_max_size: int = 5000
    workers: int = 4
    max_attempts: int = 3
    retry_base_seconds: float = 1.0


@dataclass
class OperationsConfig:
    maintenance_interval_seconds: int = 60
    inbox_retention_days: int = 7
    stale_claim_seconds: int = 600
    # Zero keeps local/demo databases untouched. Production overlays should set
    # finite retention windows so terminal operational history cannot grow
    # without bound.
    data_retention_days: int = 0
    audit_retention_days: int = 0
    memory_history_retention_days: int = 0
    retention_batch_size: int = 200


@dataclass
class MemoryMatchingConfig:
    """Deterministic memory association policy shared by every LLM backend."""

    candidate_limit: int = 100
    top_k: int = 5
    review_threshold: float = 0.58
    apply_threshold: float = 0.78
    structured_weight: float = 0.68
    semantic_weight: float = 0.22
    retrieval_weight: float = 0.10
    vector_dimensions: int = 256


@dataclass
class SyslogConfig:
    """Port-based syslog routing for collector/demo validation.

    Production should still run a dedicated collector, but keeping the same
    product-to-port contract in application config lets tests and local demos
    verify that mixed security systems are not misclassified by content alone.
    """

    product_ports: dict[str, int] = field(
        default_factory=lambda: {
            "waf": 15140,
            "hips": 15141,
            "ndr": 15142,
            "rasp": 15143,
            "siem": 15144,
        }
    )
    product_protocols: dict[str, str] = field(
        default_factory=lambda: {
            "waf": "tcp",
            "hips": "tcp",
            "ndr": "tcp",
            "rasp": "tcp",
            "siem": "tcp",
        }
    )
    gateway_profiles: dict[str, str] = field(
        default_factory=lambda: {
            "waf": "auto-waf-json",
            "hips": "auto-hips-json",
            "ndr": "auto-ndr-json",
            "rasp": "auto-rasp-json",
            "siem": "auto-siem-json",
        }
    )
    embedded_listeners_enabled: bool = False
    max_frame_bytes: int = 1_000_000
    max_connections: int = 64


@dataclass
class GatewayConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    processing: ProcessingConfig = field(default_factory=ProcessingConfig)
    operations: OperationsConfig = field(default_factory=OperationsConfig)
    memory_matching: MemoryMatchingConfig = field(default_factory=MemoryMatchingConfig)
    syslog: SyslogConfig = field(default_factory=SyslogConfig)


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
    processing = raw.get("processing", {})
    operations = raw.get("operations", {})
    memory_matching = raw.get("memory_matching", {})
    syslog = raw.get("syslog", {})
    api_key_env = str(llm.get("api_key_env", "DEFENSIVE_AI_LLM_API_KEY"))
    default_syslog = SyslogConfig()
    named_principals: list[AuthPrincipalConfig] = []
    for actor, principal in dict(auth.get("principals", {}) or {}).items():
        if not isinstance(principal, dict):
            continue
        token_env = str(principal.get("token_env", "")).strip()
        token = str(
            os.getenv(token_env, principal.get("token", ""))
            if token_env
            else principal.get("token", "")
        )
        roles = [
            str(role).strip().lower()
            for role in list(principal.get("roles", []) or [])
            if str(role).strip()
        ]
        named_principals.append(
            AuthPrincipalConfig(actor=str(actor).strip(), token=token, roles=roles)
        )
    allowed_hosts_env = os.getenv("DEFENSIVE_AI_LLM_ALLOWED_HOSTS")
    allowed_hosts = (
        [item.strip() for item in allowed_hosts_env.split(",") if item.strip()]
        if allowed_hosts_env is not None
        else list(llm.get("allowed_hosts", []) or [])
    )

    config = GatewayConfig(
        server=ServerConfig(
            host=str(os.getenv("DEFENSIVE_AI_HOST", server.get("host", "127.0.0.1"))),
            port=int(os.getenv("DEFENSIVE_AI_PORT", server.get("port", 8080))),
            max_connections=max(8, min(int(server.get("max_connections", 128)), 2048)),
            read_timeout_seconds=max(1, min(int(server.get("read_timeout_seconds", 15)), 120)),
            requests_per_minute=max(60, min(int(server.get("requests_per_minute", 6000)), 1_000_000)),
        ),
        database=DatabaseConfig(path=str(os.getenv("DEFENSIVE_AI_DB", database.get("path", "data/gateway.db")))),
        llm=LLMConfig(
            provider=str(os.getenv("DEFENSIVE_AI_LLM_PROVIDER", llm.get("provider", "local"))),
            endpoint=str(os.getenv("DEFENSIVE_AI_LLM_ENDPOINT", llm.get("endpoint", ""))),
            api_key_env=api_key_env,
            api_key=str(os.getenv(api_key_env, llm.get("api_key", ""))),
            model=str(os.getenv("DEFENSIVE_AI_LLM_MODEL", llm.get("model", "local-rule-analyst"))),
            timeout_seconds=max(1, min(int(llm.get("timeout_seconds", 30)), 300)),
            allowed_hosts=[
                str(item).strip().lower()
                for item in allowed_hosts
                if str(item).strip()
            ],
            max_response_bytes=max(65_536, min(int(llm.get("max_response_bytes", 2_000_000)), 10_000_000)),
            max_retries=max(0, min(int(llm.get("max_retries", 1)), 3)),
        ),
        policy=PolicyConfig(
            mode=str(policy.get("mode", "read_only")),
            max_prompt_chars=int(policy.get("max_prompt_chars", 12000)),
            max_context_bytes=int(policy.get("max_context_bytes", 20000)),
            approval_quorum=max(
                1,
                min(
                    int(os.getenv("DEFENSIVE_AI_APPROVAL_QUORUM", policy.get("approval_quorum", 1))),
                    5,
                ),
            ),
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
            ingest_token=str(os.getenv("DEFENSIVE_AI_INGEST_TOKEN", auth.get("ingest_token", ""))),
            operator_token=str(os.getenv("DEFENSIVE_AI_OPERATOR_TOKEN", auth.get("operator_token", ""))),
            approver_token=str(os.getenv("DEFENSIVE_AI_APPROVER_TOKEN", auth.get("approver_token", ""))),
            allow_loopback_no_token=str(
                os.getenv("DEFENSIVE_AI_AUTH_LOOPBACK", "1" if auth.get("allow_loopback_no_token", True) else "0")
            )
            in {"1", "true", "True", "yes"},
            require_token_when_remote=str(
                os.getenv("DEFENSIVE_AI_AUTH_REQUIRE_REMOTE_TOKEN", "1" if auth.get("require_token_when_remote", True) else "0")
            )
            in {"1", "true", "True", "yes"},
            demo_mode=str(
                os.getenv("DEFENSIVE_AI_DEMO_MODE", "1" if auth.get("demo_mode", False) else "0")
            )
            in {"1", "true", "True", "yes"},
            principals=named_principals,
        ),
        processing=ProcessingConfig(
            async_enabled=str(
                os.getenv("DEFENSIVE_AI_ASYNC_ALERTS", "1" if processing.get("async_enabled", True) else "0")
            )
            in {"1", "true", "True", "yes"},
            queue_max_size=int(os.getenv("DEFENSIVE_AI_QUEUE_MAX_SIZE", processing.get("queue_max_size", 5000))),
            workers=int(os.getenv("DEFENSIVE_AI_WORKERS", processing.get("workers", 4))),
            max_attempts=max(1, min(int(processing.get("max_attempts", 3)), 20)),
            retry_base_seconds=max(0.1, min(float(processing.get("retry_base_seconds", 1.0)), 300.0)),
        ),
        operations=OperationsConfig(
            maintenance_interval_seconds=max(10, min(int(operations.get("maintenance_interval_seconds", 60)), 3600)),
            inbox_retention_days=max(1, min(int(operations.get("inbox_retention_days", 7)), 365)),
            stale_claim_seconds=max(30, min(int(operations.get("stale_claim_seconds", 600)), 86400)),
            data_retention_days=max(
                0,
                min(
                    int(os.getenv("DEFENSIVE_AI_DATA_RETENTION_DAYS", operations.get("data_retention_days", 0))),
                    3650,
                ),
            ),
            audit_retention_days=max(
                0,
                min(
                    int(os.getenv("DEFENSIVE_AI_AUDIT_RETENTION_DAYS", operations.get("audit_retention_days", 0))),
                    3650,
                ),
            ),
            memory_history_retention_days=max(
                0,
                min(
                    int(
                        os.getenv(
                            "DEFENSIVE_AI_MEMORY_EVENT_RETENTION_DAYS",
                            operations.get("memory_history_retention_days", 0),
                        )
                    ),
                    3650,
                ),
            ),
            retention_batch_size=max(
                10,
                min(int(operations.get("retention_batch_size", 200)), 1000),
            ),
        ),
        memory_matching=MemoryMatchingConfig(
            candidate_limit=max(1, min(int(memory_matching.get("candidate_limit", 100)), 500)),
            top_k=max(1, min(int(memory_matching.get("top_k", 5)), 20)),
            review_threshold=float(memory_matching.get("review_threshold", 0.58)),
            apply_threshold=float(memory_matching.get("apply_threshold", 0.78)),
            structured_weight=float(memory_matching.get("structured_weight", 0.68)),
            semantic_weight=float(memory_matching.get("semantic_weight", 0.22)),
            retrieval_weight=float(memory_matching.get("retrieval_weight", 0.10)),
            vector_dimensions=max(64, min(int(memory_matching.get("vector_dimensions", 256)), 2048)),
        ),
        syslog=SyslogConfig(
            product_ports={
                **default_syslog.product_ports,
                **{str(k): int(v) for k, v in dict(syslog.get("product_ports", {}) or {}).items()},
            },
            product_protocols={
                **default_syslog.product_protocols,
                **{str(k): str(v).lower() for k, v in dict(syslog.get("product_protocols", {}) or {}).items()},
            },
            gateway_profiles={
                **default_syslog.gateway_profiles,
                **{str(k): str(v) for k, v in dict(syslog.get("gateway_profiles", {}) or {}).items()},
            },
            embedded_listeners_enabled=str(
                os.getenv(
                    "DEFENSIVE_AI_EMBEDDED_SYSLOG",
                    "1" if syslog.get("embedded_listeners_enabled", False) else "0",
                )
            )
            in {"1", "true", "True", "yes"},
            max_frame_bytes=max(1024, min(int(syslog.get("max_frame_bytes", 1_000_000)), 10_000_000)),
            max_connections=max(1, min(int(syslog.get("max_connections", 64)), 1024)),
        ),
    )
    return config
