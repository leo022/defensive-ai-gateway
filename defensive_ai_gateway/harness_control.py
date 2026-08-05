from __future__ import annotations

from typing import Any

from .config import GatewayConfig
from .models import new_id
from .response_agent import CONTROLLER_TOOLS, MANDATORY_TOOLS


HARNESS_PROFILE_ID = "response-investigation"
HARNESS_SCHEMA_VERSION = "agent-harness-profile/v1"

_AGENT_LIMITS = {
    "max_turns": (18, 128),
    "max_tool_calls": (16, 80),
    "max_wall_seconds": (30, 3_600),
    "tool_result_max_bytes": (32_000, 256_000),
    "correlation_window_minutes": (15, 10_080),
    "correlation_scan_limit": (100, 10_000),
    "correlation_scan_max_bytes": (1_000_000, 512_000_000),
    "raw_chunk_max_bytes": (2_048, 6_144),
}

FIXED_HARNESS_CONTROLS = (
    {
        "control_id": "case_scope",
        "category": "scope",
        "enforcement": "locked",
    },
    {
        "control_id": "controller_scoped_read_only",
        "category": "tooling",
        "enforcement": "locked",
    },
    {
        "control_id": "immutable_source_snapshot",
        "category": "evidence",
        "enforcement": "locked",
    },
    {
        "control_id": "evidence_reference_validation",
        "category": "validation",
        "enforcement": "locked",
    },
    {
        "control_id": "prompt_injection_review",
        "category": "validation",
        "enforcement": "locked",
    },
    {
        "control_id": "sensitive_output_block",
        "category": "validation",
        "enforcement": "locked",
    },
    {
        "control_id": "no_direct_production_execution",
        "category": "execution",
        "enforcement": "locked",
    },
)


def _profile_settings(config: GatewayConfig) -> dict[str, Any]:
    agent = config.response_agent
    return {
        "response_agent": {
            key: int(getattr(agent, key)) for key in _AGENT_LIMITS
        },
        "approval": {"quorum": int(config.policy.approval_quorum)},
    }


def _integer_setting(value: Any, key: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    try:
        rendered = str(value).strip()
        if not rendered or any(character not in "-0123456789" for character in rendered):
            raise ValueError
        return int(rendered)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer") from exc


class AgentHarnessControlService:
    """Version and publish the bounded runtime settings that operators may change."""

    def __init__(
        self,
        repo,
        config: GatewayConfig,
        *,
        minimum_approval_quorum: int,
        maximum_approval_quorum: int,
    ):
        self.repo = repo
        self.config = config
        self.minimum_approval_quorum = max(1, int(minimum_approval_quorum))
        self.maximum_approval_quorum = max(
            self.minimum_approval_quorum, int(maximum_approval_quorum)
        )
        self.deployment_defaults = _profile_settings(config)

    def _normalize(
        self,
        payload: dict[str, Any],
        *,
        defaults: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("agent harness profile must be an object")
        unexpected = set(payload) - {
            "profile_id",
            "version",
            "name",
            "description",
            "schema_version",
            "status",
            "settings",
            "created_by",
            "created_at_ms",
            "published_by",
            "published_at_ms",
            "_actor",
        }
        if unexpected:
            raise ValueError(
                "unsupported agent harness profile fields: "
                + ", ".join(sorted(unexpected))
            )
        profile_id = str(payload.get("profile_id") or HARNESS_PROFILE_ID).strip()
        if profile_id != HARNESS_PROFILE_ID:
            raise ValueError("unsupported agent harness profile id")
        name = " ".join(
            str(payload.get("name") or "Response Investigation Harness").split()
        )
        description = str(payload.get("description") or "").strip()
        if len(name) < 2 or len(name) > 100:
            raise ValueError("agent harness profile name must contain 2-100 characters")
        if len(description) > 1_000:
            raise ValueError("agent harness profile description is too long")

        baseline = defaults or self.deployment_defaults
        raw_settings = payload.get("settings") or {}
        if not isinstance(raw_settings, dict):
            raise ValueError("agent harness settings must be an object")
        unexpected_settings = set(raw_settings) - {"response_agent", "approval"}
        if unexpected_settings:
            raise ValueError(
                "unsupported agent harness settings: "
                + ", ".join(sorted(unexpected_settings))
            )
        raw_agent = raw_settings.get("response_agent") or {}
        raw_approval = raw_settings.get("approval") or {}
        if not isinstance(raw_agent, dict) or not isinstance(raw_approval, dict):
            raise ValueError("agent harness setting groups must be objects")
        unexpected_agent = set(raw_agent) - set(_AGENT_LIMITS)
        unexpected_approval = set(raw_approval) - {"quorum"}
        if unexpected_agent or unexpected_approval:
            raise ValueError("agent harness setting contains a locked or unknown field")

        normalized_agent: dict[str, int] = {}
        for key, (minimum, maximum) in _AGENT_LIMITS.items():
            value = _integer_setting(
                raw_agent.get(
                    key,
                    baseline.get("response_agent", {}).get(
                        key, self.deployment_defaults["response_agent"][key]
                    ),
                ),
                key,
            )
            if value < minimum or value > maximum:
                raise ValueError(
                    f"{key} must be between {minimum} and {maximum}"
                )
            normalized_agent[key] = value
        quorum = _integer_setting(
            raw_approval.get(
                "quorum",
                baseline.get("approval", {}).get(
                    "quorum", self.deployment_defaults["approval"]["quorum"]
                ),
            ),
            "approval quorum",
        )
        if not self.minimum_approval_quorum <= quorum <= self.maximum_approval_quorum:
            raise ValueError(
                "approval quorum must be between "
                f"{self.minimum_approval_quorum} and {self.maximum_approval_quorum}"
            )
        return {
            "profile_id": profile_id,
            "name": name,
            "description": description,
            "schema_version": HARNESS_SCHEMA_VERSION,
            "settings": {
                "response_agent": normalized_agent,
                "approval": {"quorum": quorum},
            },
        }

    def _safe_default_profile(self) -> dict[str, Any]:
        return self._normalize(
            {
                "profile_id": HARNESS_PROFILE_ID,
                "name": "Response Investigation Harness",
                "description": (
                    "Controller-scoped investigation budgets and approval policy. "
                    "Locked controls cannot be weakened from the console."
                ),
                "settings": self.deployment_defaults,
            }
        )

    def ensure_active(self) -> dict[str, Any]:
        active = self.repo.active_agent_harness_profile(HARNESS_PROFILE_ID)
        restore_error = ""
        if active:
            try:
                self._normalize(active, defaults=self.deployment_defaults)
                return active
            except (TypeError, ValueError) as exc:
                restore_error = str(exc)
        profile = self._safe_default_profile()
        with self.repo.transaction():
            created = self.repo.create_agent_harness_profile_version(
                profile, actor="system-bootstrap", _commit=False
            )
            published = self.repo.publish_agent_harness_profile(
                HARNESS_PROFILE_ID,
                int(created["version"]),
                actor="system-bootstrap",
                _commit=False,
            )
            self.repo.insert_audit(
                new_id("audit"),
                "agent-harness",
                "system-bootstrap",
                (
                    "agent_harness_profile_restore_rejected"
                    if restore_error
                    else "agent_harness_profile_seeded"
                ),
                {
                    "profile_id": HARNESS_PROFILE_ID,
                    "version": int(created["version"]),
                    "restore_error": restore_error,
                },
                _commit=False,
            )
        return published or created

    def apply(self, profile: dict[str, Any]) -> None:
        normalized = self._normalize(profile, defaults=self.deployment_defaults)
        agent_settings = normalized["settings"]["response_agent"]
        for key, value in agent_settings.items():
            setattr(self.config.response_agent, key, int(value))
        self.config.response_agent.profile_id = str(profile["profile_id"])
        self.config.response_agent.profile_version = int(profile["version"])
        self.config.policy.approval_quorum = int(
            normalized["settings"]["approval"]["quorum"]
        )

    def create_version(self, payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
        active = self.repo.active_agent_harness_profile(HARNESS_PROFILE_ID)
        defaults = active.get("settings") if active else self.deployment_defaults
        profile = self._normalize(payload, defaults=defaults)
        with self.repo.transaction():
            saved = self.repo.create_agent_harness_profile_version(
                profile, actor=actor, _commit=False
            )
            self.repo.insert_audit(
                new_id("audit"),
                "agent-harness",
                actor,
                "agent_harness_profile_draft_created",
                {
                    "profile_id": saved["profile_id"],
                    "version": int(saved["version"]),
                    "schema_version": saved["schema_version"],
                },
                _commit=False,
            )
        return saved

    def publish(self, version: int, *, actor: str) -> dict[str, Any]:
        target = self.repo.get_agent_harness_profile(HARNESS_PROFILE_ID, int(version))
        if not target:
            raise KeyError("agent harness profile not found")
        self._normalize(target, defaults=self.deployment_defaults)
        with self.repo.transaction():
            published = self.repo.publish_agent_harness_profile(
                HARNESS_PROFILE_ID,
                int(version),
                actor=actor,
                _commit=False,
            )
            if not published:
                raise KeyError("agent harness profile not found")
            self.repo.insert_audit(
                new_id("audit"),
                "agent-harness",
                actor,
                "agent_harness_profile_published",
                {
                    "profile_id": HARNESS_PROFILE_ID,
                    "version": int(version),
                    "applies_to": ["future_agent_sessions", "future_approvals"],
                },
                _commit=False,
            )
        return published

    def payload(self) -> dict[str, Any]:
        active = self.repo.active_agent_harness_profile(HARNESS_PROFILE_ID)
        return {
            "active": active,
            "versions": self.repo.list_agent_harness_profiles(HARNESS_PROFILE_ID),
            "constraints": {
                "response_agent": {
                    key: {"min": minimum, "max": maximum}
                    for key, (minimum, maximum) in _AGENT_LIMITS.items()
                },
                "approval": {
                    "quorum": {
                        "min": self.minimum_approval_quorum,
                        "max": self.maximum_approval_quorum,
                    }
                },
            },
            "fixed_controls": [dict(item) for item in FIXED_HARNESS_CONTROLS],
            "tools": [
                {
                    "name": name,
                    "mode": "controller_scoped_read_only",
                    "mandatory": name in MANDATORY_TOOLS,
                    "editable": False,
                }
                for name in CONTROLLER_TOOLS
            ],
            "change_scope": {
                "future_agent_sessions": True,
                "future_approvals": True,
                "existing_sessions_immutable": True,
                "existing_approvals_immutable": True,
            },
        }
