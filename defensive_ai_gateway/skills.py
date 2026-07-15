from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


SUPPORTED_RISK_LEVELS = {"read_only", "approval_required"}


@dataclass(frozen=True)
class SkillManifest:
    name: str
    version: str
    owner: str
    product: str
    capability: str
    risk_level: str
    allowed_inputs: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    blocked_tools: tuple[str, ...]
    output_schema: str
    memory_namespace: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in ("allowed_inputs", "allowed_tools", "blocked_tools"):
            payload[key] = list(payload[key])
        return payload


def _product_skill(product: str, capability: str, tools: tuple[str, ...]) -> SkillManifest:
    return SkillManifest(
        name=f"{product}_{capability}",
        version="2.0.0",
        owner="SOC-AI-Platform",
        product=product,
        capability=capability,
        risk_level="read_only",
        allowed_inputs=("normalized_event", "case_memory", "evidence_refs", "cross_product_context"),
        allowed_tools=tools,
        blocked_tools=("execute_production_action", "export_raw_evidence", "open_network_scan"),
        output_schema="security-analysis-v2",
        memory_namespace=f"product/{product}",
    )


class SkillRegistry:
    """Versioned, fail-closed capability registry for the phase-two runtime."""

    def __init__(self, manifests: list[SkillManifest] | None = None):
        defaults = [
            _product_skill("waf", "false_positive_review", ("query_case_evidence", "query_approved_memory")),
            _product_skill("rasp", "exploit_reachability_review", ("query_case_evidence", "query_approved_memory")),
            _product_skill("hips", "host_behavior_review", ("query_case_evidence", "query_approved_memory")),
            _product_skill("ndr", "network_timeline_review", ("query_case_evidence", "query_approved_memory")),
            _product_skill("siem", "case_fusion_review", ("query_case_evidence", "query_approved_memory")),
            SkillManifest(
                name="evidence_policy_validator",
                version="2.0.0",
                owner="Security-Architecture",
                product="all",
                capability="validate",
                risk_level="read_only",
                allowed_inputs=("normalized_event", "agent_result", "skill_manifest"),
                allowed_tools=(),
                blocked_tools=("execute_production_action", "export_raw_evidence", "network_access"),
                output_schema="validation-result-v1",
                memory_namespace="none",
            ),
            SkillManifest(
                name="controlled_response_advisor",
                version="2.0.0",
                owner="SOC-Response",
                product="all",
                capability="advise_response",
                risk_level="approval_required",
                allowed_inputs=("agent_result", "validation_result"),
                allowed_tools=("create_approval_request",),
                blocked_tools=("execute_production_action", "call_soar_directly", "change_security_policy"),
                output_schema="approval-request-v1",
                memory_namespace="none",
            ),
        ]
        self._manifests: dict[str, SkillManifest] = {}
        for manifest in manifests or defaults:
            self.register(manifest)

    def register(self, manifest: SkillManifest) -> None:
        if not manifest.name or not manifest.version or not manifest.owner:
            raise ValueError("skill name, version and owner are required")
        if manifest.risk_level not in SUPPORTED_RISK_LEVELS:
            raise ValueError(f"unsupported skill risk level: {manifest.risk_level}")
        overlap = set(manifest.allowed_tools) & set(manifest.blocked_tools)
        if overlap:
            raise ValueError(f"skill tools cannot be both allowed and blocked: {sorted(overlap)}")
        if "execute_production_action" not in manifest.blocked_tools:
            raise ValueError("phase-two skills must explicitly block execute_production_action")
        self._manifests[manifest.name] = manifest

    def get(self, name: str) -> SkillManifest:
        try:
            return self._manifests[name]
        except KeyError as exc:
            raise ValueError(f"skill not found: {name}") from exc

    def for_product(self, product: str) -> SkillManifest:
        product = product.strip().lower()
        matches = [m for m in self._manifests.values() if m.product == product]
        if len(matches) != 1:
            raise ValueError(f"exactly one analysis skill required for product: {product}")
        return matches[0]

    def list(self) -> list[dict[str, Any]]:
        return [self._manifests[name].to_dict() for name in sorted(self._manifests)]
