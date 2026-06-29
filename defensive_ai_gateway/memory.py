from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .database import Repository
from .models import AgentResult, new_id, now_ms

# Multi-layer memory management, following the architecture design §8
# "多层记忆 + 一层证据" and §6 Memory Manager / §11 记忆投毒控制.
#
# Layers (each with its own namespace + retrieval key + governance rule):
#   case_short_term   — case_id / trace_id        — archived on case close; promote needs approval
#   product_long_term — product / rule_id / asset — quarterly review; expired auto-deweight
#   asset_profile     — asset_id / app_id / owner — sensitive fields minimized
#   org_knowledge     — policy / playbook / dept  — governance-team maintained, changes via review
#   evidence          — immutable evidence_ref    — read-only; agents only see desensitized summaries
#
# Promotion rule (five gates, all must hold to promote a case observation to long-term):
#   evidence_traceable + analyst_approved + scope_clear + expiry_set + no_sensitive_leak

LAYER_CASE_SHORT_TERM = "case_short_term"
LAYER_PRODUCT_LONG_TERM = "product_long_term"
LAYER_ASSET_PROFILE = "asset_profile"
LAYER_ORG_KNOWLEDGE = "org_knowledge"
LAYER_EVIDENCE = "evidence"

STATUS_ACTIVE = "active"
STATUS_PENDING = "pending_approval"
STATUS_EXPIRED = "expired"
STATUS_QUARANTINED = "quarantined"
STATUS_REVOKED = "revoked"

TRUST_LOW = "low"
TRUST_MEDIUM = "medium"
TRUST_HIGH = "high"

PROMOTION_GATES = [
    "evidence_traceable",
    "analyst_approved",
    "scope_clear",
    "expiry_set",
    "no_sensitive_leak",
]

SHORT_TERM_TTL_MS = 24 * 3600 * 1000  # short-term case memory archived after 24h
QUARTERLY_REVIEW_MS = 90 * 24 * 3600 * 1000

# Governance-team maintained organizational knowledge, seeded on first use.
# Changes in production must go through review; these are read-only defaults.
DEFAULT_ORG_KNOWLEDGE = [
    {"scope": "playbook", "retrieval_key": "phishing", "content": "钓鱼研判 playbook：核实发件域、MFA 状态、凭证是否泄露；高影响动作走审批链。"},
    {"scope": "playbook", "retrieval_key": "lateral_movement", "content": "横向移动 playbook：关联 HIPS 进程链与 NDR 流量，主机隔离需审批。"},
    {"scope": "policy", "retrieval_key": "incident_grading", "content": "事件分级：critical/high 由 SOC 二线确认；AI 仅给建议，不自动变更。"},
    {"scope": "policy", "retrieval_key": "approval_chain", "content": "审批链：封禁/隔离/策略变更需安全负责人与业务 Owner 双签。"},
    {"scope": "playbook", "retrieval_key": "comms_template", "content": "沟通模板：对外通报只引用 evidence_ref，不携带原始敏感字段。"},
]


@dataclass
class PromotionOutcome:
    ok: bool
    reasons: list[str]
    memory_id: str


class MemoryManager:
    """Manages the four memory layers plus the read-only evidence store.

    The manager is the home of the memory governance ops described in §6/§11:
    expiry sweep, poisoning quarantine, low-trust/conflict isolation, and the
    five-gate promotion rule that gates promotion from short-term case memory to
    long-term product/asset memory.
    """

    def __init__(self, repo: Repository, policy: Any = None):
        self.repo = repo
        self.policy = policy
        self._seed_org_knowledge()

    # ---- namespaces / retrieval keys ---------------------------------

    def case_namespace(self, case_id: str) -> str:
        return f"case/{case_id}"

    def product_namespace(self, product: str) -> str:
        return f"product/{product.lower()}"

    def asset_namespace(self, asset_id: str) -> str:
        return f"asset/{str(asset_id).lower()}"

    def org_namespace(self, scope: str) -> str:
        return f"org/{scope}"

    def namespace_for(self, product: str) -> str:
        """Back-compat shim for legacy callers."""
        return self.product_namespace(product)

    def asset_id_for(self, event: Any) -> str | None:
        entities = getattr(event, "entities", {}) or {}
        return entities.get("host") or entities.get("app") or entities.get("src_ip")

    # ---- organizational knowledge seeding ----------------------------

    def _seed_org_knowledge(self) -> None:
        existing = self.repo.query_memory(layer=LAYER_ORG_KNOWLEDGE, limit=1000, include_expired=True)
        have = {(m["scope"], m["retrieval_key"]) for m in existing}
        for entry in DEFAULT_ORG_KNOWLEDGE:
            if (entry["scope"], entry["retrieval_key"]) in have:
                continue
            self.repo.save_memory(
                {
                    "memory_id": new_id("mem"),
                    "layer": LAYER_ORG_KNOWLEDGE,
                    "namespace": self.org_namespace(entry["scope"]),
                    "retrieval_key": entry["retrieval_key"],
                    "content": entry["content"],
                    "source_case_id": "",
                    "scope": entry["scope"],
                    "trust_level": TRUST_HIGH,
                    "status": STATUS_ACTIVE,
                    "sensitivity_ok": True,
                    "approved_by": "security_governance",
                    "expires_at_ms": None,
                }
            )

    # ---- context loading ---------------------------------------------

    def load_context(
        self,
        product: str,
        case_id: str | None = None,
        asset_id: str | None = None,
        limit: int = 5,
    ) -> dict[str, Any]:
        """Load structured multi-layer memory for an analysis run."""
        context: dict[str, Any] = {
            "case_short_term": [],
            "product_long_term": [],
            "asset_profile": [],
            "org_knowledge": [],
            "evidence_refs": [],
        }
        if case_id:
            context["case_short_term"] = self.repo.query_memory(
                layer=LAYER_CASE_SHORT_TERM, namespace=self.case_namespace(case_id), limit=limit
            )
            context["evidence_refs"] = self.load_evidence(case_id)
        context["product_long_term"] = self._load_product_long_term(product, limit)
        if asset_id:
            context["asset_profile"] = self.repo.query_memory(
                layer=LAYER_ASSET_PROFILE, namespace=self.asset_namespace(asset_id), limit=limit
            )
        context["org_knowledge"] = self.repo.query_memory(layer=LAYER_ORG_KNOWLEDGE, limit=limit)
        return context

    def _load_product_long_term(self, product: str, limit: int) -> list[dict[str, Any]]:
        """Prefer approved active product memories before pending candidates.

        Pending candidates are useful for governance review, but they should not
        push approved memories out of the analysis context for repeated alerts.
        """
        namespace = self.product_namespace(product)
        active = self.repo.query_memory(
            layer=LAYER_PRODUCT_LONG_TERM,
            namespace=namespace,
            status=STATUS_ACTIVE,
            limit=limit,
        )
        if len(active) >= limit:
            return active
        pending = self.repo.query_memory(
            layer=LAYER_PRODUCT_LONG_TERM,
            namespace=namespace,
            status=STATUS_PENDING,
            limit=limit - len(active),
        )
        return active + pending

    def load_evidence(self, case_id: str) -> list[dict[str, Any]]:
        """Read-only immutable evidence store: desensitized refs only, never writable by agents."""
        return self.repo.load_evidence_refs(case_id)

    # ---- recording ----------------------------------------------------

    def record_case_summary(
        self, product: str, result: AgentResult, asset_id: str | None = None, trace_id: str | None = None
    ) -> None:
        if result.classification not in {"malicious", "suspicious", "benign"}:
            return
        # Write short-term case memory + long-term candidate + asset profile as one
        # atomic unit so a crash cannot leave a case with short-term memory but no
        # long-term candidate (or vice-versa).
        with self.repo.transaction():
            # 1) short-term case memory — always written, auto-expires (archive on close)
            self.repo.save_memory(
                {
                    "memory_id": new_id("mem"),
                    "layer": LAYER_CASE_SHORT_TERM,
                    "namespace": self.case_namespace(result.case_id),
                    "retrieval_key": result.case_id,
                    "content": self._case_short_term_content(result, trace_id),
                    "source_case_id": result.case_id,
                    "scope": f"case:{result.case_id}",
                    "trust_level": TRUST_LOW,
                    "status": STATUS_ACTIVE,
                    "sensitivity_ok": True,
                    "approved_by": "",
                    "expires_at_ms": now_ms() + SHORT_TERM_TTL_MS,
                },
                _commit=False,
            )
            # 2) propose a long-term candidate — NOT auto-promoted; pending analyst approval
            self._propose_long_term_locked(product, result, asset_id)
            # 3) asset profile — low-trust operational context, useful for same-asset review
            if asset_id:
                self._record_asset_profile_locked(product, result, asset_id)

    def _propose_long_term_locked(self, product: str, result: AgentResult, asset_id: str | None = None) -> str:
        """Long-term candidate proposal assuming the caller holds a transaction.

        Public ``propose_long_term`` wraps this in its own transaction for callers
        that propose outside ``record_case_summary``.
        """
        memory_id = new_id("mem")
        self.repo.save_memory(
            {
                "memory_id": memory_id,
                "layer": LAYER_PRODUCT_LONG_TERM,
                "namespace": self.product_namespace(product),
                "retrieval_key": result.case_id,
                "content": self._long_term_candidate_content(product, result, asset_id),
                "source_case_id": result.case_id,
                "scope": "",  # unset → blocks promotion (scope_clear gate)
                "trust_level": TRUST_LOW,
                "status": STATUS_PENDING,
                "sensitivity_ok": True,
                "approved_by": "",  # unset → blocks promotion (analyst_approved gate)
                "expires_at_ms": None,  # unset → blocks promotion (expiry_set gate)
            },
            _commit=False,
        )
        self.repo.insert_memory_event(
            new_id("mev"), memory_id, LAYER_PRODUCT_LONG_TERM, "proposed", "memory_manager",
            {"case_id": result.case_id, "product": product, "asset_id": asset_id}, _commit=False,
        )
        return memory_id

    def _case_short_term_content(self, result: AgentResult, trace_id: str | None) -> str:
        return json.dumps(
            {
                "case_id": result.case_id,
                "trace_id": trace_id,
                "classification": result.classification,
                "severity": result.severity,
                "confidence": result.confidence,
                "summary": result.summary,
                "verdict": result.explanation.get("verdict"),
                "analysis_dimensions": result.explanation.get("dimensions", []),
                "whitelist_recommendation": result.explanation.get("whitelist_recommendation"),
                "missing_evidence": result.missing_evidence,
            },
            ensure_ascii=False,
        )

    def propose_long_term(self, product: str, result: AgentResult, asset_id: str | None = None) -> str:
        """Propose a product long-term memory candidate (status=pending_approval).

        Scope and expiry are intentionally unset so the promotion gates block it
        until an analyst confirms.
        """
        with self.repo.transaction():
            return self._propose_long_term_locked(product, result, asset_id)

    def _long_term_candidate_content(self, product: str, result: AgentResult, asset_id: str | None) -> str:
        whitelist = result.explanation.get("whitelist_recommendation") or {}
        dimensions = result.explanation.get("dimensions", [])
        return json.dumps(
            {
                "product": product,
                "asset_id": asset_id,
                "classification": result.classification,
                "severity": result.severity,
                "confidence": result.confidence,
                "verdict": result.explanation.get("verdict"),
                "summary": result.summary,
                "dimension_titles": [item.get("title") for item in dimensions if isinstance(item, dict)],
                "whitelist_recommendation": whitelist,
                "false_positive_candidate": result.classification == "benign" or bool(whitelist),
                "similarity_features": self._similarity_features_from_result(result, whitelist),
                "missing_evidence": result.missing_evidence,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

    def _similarity_features_from_result(self, result: AgentResult, whitelist: dict[str, Any] | str) -> list[str]:
        text_parts = [result.case_id, result.summary, result.explanation.get("verdict", "")]
        if isinstance(whitelist, dict):
            text_parts.extend(str(v) for v in whitelist.values() if v)
        else:
            text_parts.append(str(whitelist))
        return sorted(self._extract_similarity_features(" ".join(text_parts)))[:16]

    def record_asset_profile(self, product: str, result: AgentResult, asset_id: str) -> str:
        with self.repo.transaction():
            return self._record_asset_profile_locked(product, result, asset_id)

    def _record_asset_profile_locked(self, product: str, result: AgentResult, asset_id: str) -> str:
        """Caller holds a transaction."""
        memory_id = new_id("mem")
        self.repo.save_memory(
            {
                "memory_id": memory_id,
                "layer": LAYER_ASSET_PROFILE,
                "namespace": self.asset_namespace(asset_id),
                "retrieval_key": asset_id,
                "content": json.dumps(
                    {
                        "asset_id": asset_id,
                        "product": product,
                        "last_case_id": result.case_id,
                        "last_classification": result.classification,
                        "last_severity": result.severity,
                        "last_verdict": result.explanation.get("verdict"),
                        "summary": result.summary,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "source_case_id": result.case_id,
                "scope": f"asset:{asset_id}",
                "trust_level": TRUST_LOW,
                "status": STATUS_ACTIVE,
                "sensitivity_ok": True,
                "approved_by": "memory_manager",
                "expires_at_ms": now_ms() + QUARTERLY_REVIEW_MS,
            },
            _commit=False,
        )
        self.repo.insert_memory_event(
            new_id("mev"), memory_id, LAYER_ASSET_PROFILE, "asset_profile_recorded", "memory_manager",
            {"case_id": result.case_id, "product": product, "asset_id": asset_id}, _commit=False,
        )
        return memory_id

    def confirm_business_false_positive(
        self,
        linked_alert: dict[str, Any],
        analyst: str,
        reason: str,
        expires_at_ms: int | None = None,
    ) -> dict[str, Any]:
        raw = linked_alert.get("raw_alert") or {}
        normalized = linked_alert.get("normalized_event") or {}
        product = str(raw.get("product") or normalized.get("product") or "").lower()
        if not product:
            raise ValueError("alert product is missing")
        features = self.extract_false_positive_features(linked_alert)
        content = json.dumps(
            {
                "classification": "benign",
                "false_positive_candidate": True,
                "human_confirmed": True,
                "confirmation_type": "business_false_positive",
                "confirmed_by": analyst,
                "confirmation_reason": reason,
                "product": product,
                "alert_id": linked_alert.get("alert_id"),
                "case_id": linked_alert.get("case_id"),
                "event_type": raw.get("event_type") or normalized.get("event_type"),
                "features": features,
                "similarity_features": features["similarity_features"],
                "match_policy": {
                    "must_match_any": ["product", "event_type", "rule_id"],
                    "high_similarity_threshold": 0.78,
                    "effect": "降低同类型告警置信度；高度相似时优先判定为误报并保留人工复核边界",
                },
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        memory_id = new_id("mem")
        # Atomic: the FP memory and its audit event commit together. The HTTP layer's
        # companion audit_log row is written in the same logical action (see
        # GatewayState.confirm_alert_false_positive) so a crash cannot leave a
        # promoted FP memory without a trace.
        with self.repo.transaction():
            self.repo.save_memory(
                {
                    "memory_id": memory_id,
                    "layer": LAYER_PRODUCT_LONG_TERM,
                    "namespace": self.product_namespace(product),
                    "retrieval_key": features.get("rule_id") or raw.get("event_type") or linked_alert.get("alert_id", ""),
                    "content": content,
                    "source_case_id": linked_alert.get("case_id", ""),
                    "scope": f"{product}:business_false_positive:{features.get('event_type') or raw.get('event_type')}",
                    "trust_level": TRUST_MEDIUM,
                    "status": STATUS_ACTIVE,
                    "sensitivity_ok": True,
                    "approved_by": analyst,
                    "expires_at_ms": expires_at_ms or now_ms() + QUARTERLY_REVIEW_MS,
                },
                _commit=False,
            )
            self.repo.insert_memory_event(
                new_id("mev"),
                memory_id,
                LAYER_PRODUCT_LONG_TERM,
                "human_confirmed_business_false_positive",
                analyst,
                {
                    "alert_id": linked_alert.get("alert_id"),
                    "case_id": linked_alert.get("case_id"),
                    "reason": reason,
                    "features": features,
                },
                _commit=False,
            )
        return {"memory_id": memory_id, "features": features}

    def extract_false_positive_features(self, linked_alert: dict[str, Any]) -> dict[str, Any]:
        raw = linked_alert.get("raw_alert") or {}
        normalized = linked_alert.get("normalized_event") or {}
        payload = raw.get("payload") or {}
        entities = normalized.get("entities") or {}
        product = str(raw.get("product") or normalized.get("product") or "").lower()
        event_type = str(raw.get("event_type") or normalized.get("event_type") or "")
        feature_map = {
            "product": product,
            "event_type": event_type,
            "rule_id": payload.get("rule_id") or entities.get("rule"),
            "rule_name": payload.get("rule_name"),
            "app": payload.get("app") or entities.get("app"),
            "host": payload.get("host") or payload.get("src_host") or entities.get("host"),
            "src_ip": payload.get("src_ip") or entities.get("src_ip"),
            "dst_ip": payload.get("dst_ip") or entities.get("dst_ip"),
            "method": payload.get("method") or entities.get("method"),
            "uri": payload.get("uri") or entities.get("url"),
            "route": payload.get("route"),
            "user_agent": (payload.get("headers") or {}).get("user-agent"),
            "matched_parameters": payload.get("matched_parameters"),
            "process_name": payload.get("process_name"),
            "parent_process": payload.get("parent_process"),
            "signature_status": payload.get("signature_status"),
            "sni": payload.get("sni"),
            "protocol": payload.get("protocol"),
            "dst_port": payload.get("dst_port"),
            "user": payload.get("user") or entities.get("user"),
            "mitre_tactic": payload.get("mitre_tactic"),
        }
        stable_text = json.dumps(feature_map, ensure_ascii=False, sort_keys=True)
        similarity_features = sorted(self._extract_similarity_features(stable_text))
        for key in ["rule_id", "event_type", "app", "host", "uri", "route", "user_agent", "process_name", "parent_process", "sni", "protocol"]:
            value = feature_map.get(key)
            if isinstance(value, str) and value:
                similarity_features.append(value.lower())
        similarity_features = sorted({item for item in similarity_features if item})
        return {
            **feature_map,
            "similarity_features": similarity_features[:24],
            "feature_text": stable_text,
        }

    def _extract_similarity_features(self, text: str) -> set[str]:
        import re

        features: set[str] = set()
        for pattern in [
            r"\b(?:waf|hips|rasp|ndr|siem)-[a-z0-9-]+",
            r"/[a-z0-9_./{}-]+",
            r"\b[a-z0-9_-]+(?:-api|-web|-gateway|-service|-client|-srv|-prod)(?:/[0-9.]+)?\b",
            r"\b[a-z0-9_.-]+\.(?:internal|example)\b",
            r"\b(?:synthetic-browser|synthetic-canary|bank-partner-batch-client/[0-9.]+|backup-vault\.internal|svc-patch|svc-maintenance)\b",
            r"\b(?:powershell\.exe|software_center\.exe|wmiprvse\.exe|psexesvc\.exe)\b",
        ]:
            features.update(re.findall(pattern, text, flags=re.IGNORECASE))
        normalized = {feature.strip().lower().rstrip(".,;:") for feature in features}
        return {feature for feature in normalized if len(feature) >= 4}

    # ---- promotion rule (five gates) ---------------------------------

    def promotion_check(
        self, memory_id: str, approved_by: str, scope: str, expires_at_ms: int | None
    ) -> tuple[bool, list[str]]:
        m = self.repo.get_memory(memory_id)
        if not m:
            return False, ["memory_not_found"]
        reasons: list[str] = []
        # 1) evidence traceable — source case must have immutable evidence refs
        if not m.get("source_case_id"):
            reasons.append("evidence_traceable:missing_source_case")
        elif not self.repo.load_evidence_refs(m["source_case_id"]):
            reasons.append("evidence_traceable:no_evidence_refs")
        # 2) analyst confirmed
        if not approved_by:
            reasons.append("analyst_approved:missing_approver")
        # 3) scope clear
        if not scope:
            reasons.append("scope_clear:missing_scope")
        # 4) expiry set
        if not expires_at_ms:
            reasons.append("expiry_set:missing_expiry")
        # 5) no sensitive leakage
        if not self._sensitivity_ok(m):
            reasons.append("no_sensitive_leak:sensitive_content_detected")
        return (len(reasons) == 0), reasons

    def _sensitivity_ok(self, memory: dict[str, Any]) -> bool:
        if not memory.get("sensitivity_ok", 1):
            return False
        content = memory.get("content", "") or ""
        if self.policy is not None and content:
            redacted = self.policy.redact(content)
            if redacted != content:
                # redaction changed the content → sensitive material present
                return False
        return True

    def promote(
        self,
        memory_id: str,
        approved_by: str,
        scope: str,
        expires_at_ms: int,
        retrieval_key: str | None = None,
    ) -> PromotionOutcome:
        ok, reasons = self.promotion_check(memory_id, approved_by, scope, expires_at_ms)
        if not ok:
            with self.repo.transaction():
                self.repo.insert_memory_event(
                    new_id("mev"), memory_id, LAYER_PRODUCT_LONG_TERM, "rejected",
                    approved_by or "memory_manager", {"reasons": reasons}, _commit=False,
                )
            return PromotionOutcome(False, reasons, memory_id)
        # Atomic promotion: status, scope, retrieval_key and the audit event commit
        # together so a failure mid-sequence cannot leave an ``active`` memory with
        # empty scope/retrieval_key (which would violate the very gates just checked).
        with self.repo.transaction():
            self.repo.update_memory(
                memory_id,
                status=STATUS_ACTIVE,
                approved_by=approved_by,
                expires_at_ms=expires_at_ms,
                trust_level=TRUST_MEDIUM,
                _commit=False,
            )
            if scope:
                self.repo.update_memory(memory_id, scope=scope, _commit=False)
            if retrieval_key:
                self.repo.update_memory(memory_id, retrieval_key=retrieval_key, _commit=False)
            self.repo.insert_memory_event(
                new_id("mev"), memory_id, LAYER_PRODUCT_LONG_TERM, "promoted", approved_by,
                {"scope": scope, "expires_at_ms": expires_at_ms, "retrieval_key": retrieval_key},
                _commit=False,
            )
        return PromotionOutcome(True, [], memory_id)

    def reject(self, memory_id: str, actor: str, reason: str) -> None:
        with self.repo.transaction():
            self.repo.update_memory(memory_id, status=STATUS_REVOKED, _commit=False)
            self.repo.insert_memory_event(
                new_id("mev"), memory_id, LAYER_PRODUCT_LONG_TERM, "rejected", actor, {"reason": reason},
                _commit=False,
            )

    # ---- governance: expiry, poisoning, conflicts, archival ----------

    def expire_due(self, now_ms_value: int | None = None) -> list[str]:
        """Sweep: mark active memories past their expiry as expired (auto-deweight)."""
        now_ms_value = now_ms_value if now_ms_value is not None else now_ms()
        expired: list[str] = []
        for m in self.repo.memory_due_for_expiry(now_ms_value):
            with self.repo.transaction():
                self.repo.update_memory(m["memory_id"], status=STATUS_EXPIRED, trust_level=TRUST_LOW, _commit=False)
                self.repo.insert_memory_event(
                    new_id("mev"), m["memory_id"], m["layer"], "expired", "memory_manager",
                    {"expired_at": now_ms_value, "was_expires_at": m["expires_at_ms"]},
                    _commit=False,
                )
            expired.append(m["memory_id"])
        return expired

    def quarantine(self, memory_id: str, actor: str, reason: str) -> None:
        """Isolate a low-trust / suspected-poisoned memory (§11 记忆投毒控制)."""
        with self.repo.transaction():
            self.repo.update_memory(memory_id, status=STATUS_QUARANTINED, trust_level=TRUST_LOW, _commit=False)
            self.repo.insert_memory_event(
                new_id("mev"), memory_id, "", "quarantined", actor, {"reason": reason}, _commit=False,
            )

    def detect_conflicts(self, product: str) -> list[dict[str, Any]]:
        """Detect duplicate/conflicting long-term memories for a product and quarantine the dupes."""
        rows = self.repo.query_memory(
            layer=LAYER_PRODUCT_LONG_TERM, namespace=self.product_namespace(product),
            limit=200, include_expired=False,
        )
        rows = sorted(rows, key=lambda item: (int(item.get("created_at_ms") or 0), str(item.get("memory_id") or "")))
        seen: dict[str, str] = {}
        conflicts: list[dict[str, Any]] = []
        for m in rows:
            key = m["content"]
            if key in seen:
                conflicts.append({"memory_id": m["memory_id"], "conflicts_with": seen[key]})
                self.quarantine(m["memory_id"], "memory_manager", "duplicate_conflict")
            else:
                seen[key] = m["memory_id"]
        for c in conflicts:
            self.repo.insert_memory_event(
                new_id("mev"), c["memory_id"], LAYER_PRODUCT_LONG_TERM, "conflict_detected",
                "memory_manager", {"conflicts_with": c["conflicts_with"]},
            )
        return conflicts

    def review_overdue(self, layer: str = LAYER_PRODUCT_LONG_TERM, now_ms_value: int | None = None) -> list[dict[str, Any]]:
        """Flag long-term memories older than the quarterly review window for review."""
        now_ms_value = now_ms_value if now_ms_value is not None else now_ms()
        return self.repo.memory_due_for_review(layer, now_ms_value - QUARTERLY_REVIEW_MS)

    def archive_case(self, case_id: str, actor: str = "memory_manager") -> int:
        """Compress/archive short-term case memory when a case closes (important conclusions must
        be promoted first; otherwise they expire)."""
        rows = self.repo.query_memory(
            layer=LAYER_CASE_SHORT_TERM, namespace=self.case_namespace(case_id),
            limit=200, include_expired=False,
        )
        for m in rows:
            self.repo.update_memory(m["memory_id"], status=STATUS_EXPIRED)
            self.repo.insert_memory_event(
                new_id("mev"), m["memory_id"], LAYER_CASE_SHORT_TERM, "expired", actor,
                {"reason": "case_closed_archive"},
            )
        return len(rows)
