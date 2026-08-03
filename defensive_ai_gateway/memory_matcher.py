from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .config import MemoryMatchingConfig
from .models import AgentResult, NormalizedEvent, RecommendedAction, now_ms


MATCHER_VERSION = "hybrid-memory-v5"
SEMANTIC_METHOD = "signed_lexical_hash_v1"

_FALSE_POSITIVE_MARKERS = {
    "false_positive", "false positive", "benign", "maintenance",
    "canary", "synthetic", "误报", "巡检", "演练",
}

_FALSE_POSITIVE_SCOPES = {
    "false_positive_pattern", "business_false_positive", "false_positive", "fp",
}

_FIELD_ALIASES = {
    "rule": "rule_id",
    "rule_id": "rule_id",
    "signature_id": "rule_id",
    "event_type": "event_type",
    "alert_type": "event_type",
    "app": "app",
    "application": "app",
    "service": "app",
    "service_name": "app",
    "host": "host",
    "hostname": "host",
    "asset_id": "host",
    "uri": "uri",
    "url": "uri",
    "path": "uri",
    "route": "uri",
    "method": "method",
    "http_method": "method",
    "request_method": "method",
    "process": "process",
    "process_name": "process",
    "parent_process": "process",
    "image": "process",
    "sink": "sink",
    "dangerous_call": "sink",
    "user_agent": "user_agent",
    "user-agent": "user_agent",
    "client": "user_agent",
    "src_ip": "src_ip",
    "source_ip": "src_ip",
    "dst_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "protocol": "protocol",
    "user": "user",
    "username": "user",
    "account": "user",
}

_FEATURE_WEIGHTS = {
    "rule_id": 0.25,
    "event_type": 0.15,
    "app": 0.12,
    "host": 0.08,
    "uri": 0.14,
    "method": 0.08,
    "process": 0.08,
    "sink": 0.10,
    "user_agent": 0.06,
    "src_ip": 0.025,
    "dst_ip": 0.025,
    "protocol": 0.02,
    "user": 0.02,
    "tokens": 0.03,
}

_IDENTITY_FIELDS = ("rule_id", "event_type")
_BEHAVIOR_BOUNDARY_FIELDS = ("uri", "method", "process", "sink", "user_agent")
_CONTEXT_FIELDS = ("app", "host", "dst_ip", "protocol", "user")
_MATCH_LEVEL_PRIORITY = {"exact": 0, "high": 1, "related": 2, "weak": 3}
_MATCH_LEVEL_LABELS = {
    "exact": "完全一致",
    "high": "高度相似",
    "related": "部分相似（不构成命中）",
    "weak": "相似度不足",
}
_FIELD_LABELS = {
    "rule_id": "规则",
    "event_type": "事件类型",
    "app": "应用",
    "host": "资产/目标",
    "uri": "URI",
    "method": "HTTP 方法",
    "process": "进程",
    "sink": "危险调用",
    "user_agent": "客户端",
    "src_ip": "来源 IP",
    "dst_ip": "目标 IP",
    "protocol": "协议",
    "user": "账号",
}

# Only evidence that describes the current request, payload, or process may veto
# a governed-memory downgrade.  Correlation/timeline/recent-context evidence can
# legitimately mention an older attack and must not turn that historical fact
# into a claim about the alert currently being reconciled.
_CURRENT_ATTACK_EVIDENCE_TYPES = (
    "attack_data",
    "hook_data",
    "command_line",
    "payload_category",
    "signals",
    "query",
    "uri",
    "url",
    "request",
    "request_body",
)

_CURRENT_ATTACK_PATTERN = re.compile(
    r"(?ix)(?:"
    # SQL injection: require an exploit-shaped expression rather than a lone
    # SQL keyword, which commonly appears in free-text business fields.
    r"\bunion(?:\s+all)?\s+select\b|"
    r"\b(?:or|and)\s+(?:['\"]?\d+['\"]?|['\"][^'\"]+['\"]\s*)"
    r"\s*=\s*(?:['\"]?\d+['\"]?|['\"][^'\"]+['\"]\s*)|"
    r"\b(?:sleep|benchmark)\s*\(|\binformation_schema\b|"
    r"\b(?:load_file|xp_cmdshell)\s*\(|\binto\s+(?:out|dump)file\b|"
    r"\bboolean\s+expression\b.{0,80}\bsql\s+keyword\s+markers?\b|"
    # XSS: require an executable HTML/JavaScript shape or the security
    # product's explicit combined marker, not a bare 'xss' label.
    r"<\s*script\b|\bjavascript\s*:|\bon(?:error|load|click|mouseover)\s*=|"
    r"\bdocument\s*\.\s*cookie\b|"
    r"\bscript\s+marker\b.{0,80}\bencoded\s+html(?:\s+entity)?\b|"
    # Command injection / execution.
    r"(?:;|&&|\|\||\|)\s*(?:/bin/(?:ba)?sh\b|cmd(?:\.exe)?\b|"
    r"powershell(?:\.exe)?\b|curl\b|wget\b|nc\b|netcat\b)|"
    r"\$\(\s*(?:/bin/(?:ba)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?|"
    r"curl|wget|nc|netcat)\b|"
    r"\b(?:os\s+)?command[_ -]?injection\b|"
    # Path traversal / local-file inclusion.
    r"(?:\.\.[/\\]){2,}|(?:%2e){2}(?:%2f|%5c)|"
    r"\b(?:directory|path)\s+traversal\s+markers?\b|"
    r"/(?:etc/passwd|proc/self/environ)\b|\bwindows[/\\]win\.ini\b|"
    # Existing high-confidence execution and malware indicators.
    r"\bjndi\b|ldap://|rmi://|\bmimikatz\b|credential\s*dump|"
    r"reverse\s*shell|downloadstring|frombase64string|"
    r"powershell(?:\.exe)?\s+-(?:enc|encodedcommand)\b|"
    r"/bin/(?:ba)?sh\b|cmd\.exe\s+/c\b|cobalt\s*strike|\bmalware\b|"
    r"\bcommand[_ -]?execution\b"
    r")"
)


@dataclass
class MemoryMatchCandidate:
    memory_id: str
    memory: dict[str, Any]
    structured_score: float
    semantic_score: float
    retrieval_score: float
    overall_score: float
    matched_features: list[str]
    score_breakdown: dict[str, float]
    match_level: str = "weak"
    title_eligible: bool = False
    comparison: dict[str, Any] = field(default_factory=dict)
    apply_threshold: float = 1.0
    policy_effect: str = "downgrade_to_benign"
    rank: int = 0
    decision: str = "ignored"

    def to_dict(self, include_memory: bool = False) -> dict[str, Any]:
        payload = {
            "memory_id": self.memory_id,
            "rank": self.rank,
            "structured_score": self.structured_score,
            "semantic_score": self.semantic_score,
            "retrieval_score": self.retrieval_score,
            "overall_score": self.overall_score,
            "matched_features": list(self.matched_features),
            "score_breakdown": dict(self.score_breakdown),
            "match_level": self.match_level,
            "title_eligible": self.title_eligible,
            "comparison": dict(self.comparison),
            "decision": self.decision,
            "apply_threshold": self.apply_threshold,
            "policy_effect": self.policy_effect,
        }
        if include_memory:
            payload["memory"] = self.memory
        return payload


@dataclass
class MemoryMatchEvaluation:
    event_id: str
    alert_id: str
    product: str
    matcher_version: str
    review_threshold: float
    apply_threshold: float
    candidates: list[MemoryMatchCandidate] = field(default_factory=list)
    best_memory_id: str = ""
    final_effect: str = "none"
    attack_signal_veto: bool = False
    attack_signal_reasons: list[str] = field(default_factory=list)
    config_snapshot: dict[str, Any] = field(default_factory=dict)

    @property
    def best(self) -> MemoryMatchCandidate | None:
        if not self.best_memory_id:
            return None
        return next((item for item in self.candidates if item.memory_id == self.best_memory_id), None)

    def context_payload(self, top_k: int, *, title_eligible_only: bool = False) -> dict[str, Any]:
        visible = [
            item.to_dict()
            for item in self.candidates
            if item.overall_score >= self.review_threshold
            and (item.title_eligible or not title_eligible_only)
        ][:top_k]
        return {
            "matcher_version": self.matcher_version,
            "review_threshold": self.review_threshold,
            "apply_threshold": self.apply_threshold,
            "best_memory_id": self.best_memory_id,
            "matches": visible,
            "attack_signal_veto": self.attack_signal_veto,
            "attack_signal_reasons": list(self.attack_signal_reasons),
            "config_snapshot": dict(self.config_snapshot),
        }


class HashingTextVectorizer:
    """Offline lexical-hash vectorizer; replaceable by an enterprise embedder."""

    def __init__(self, dimensions: int = 256):
        self.dimensions = max(64, int(dimensions))

    def cosine(self, left: str, right: str) -> float:
        left_vector = self.vectorize(left)
        right_vector = self.vectorize(right)
        if not left_vector or not right_vector:
            return 0.0
        dot = sum(value * right_vector.get(index, 0.0) for index, value in left_vector.items())
        return max(0.0, min(1.0, dot))

    def vectorize(self, text: str) -> dict[int, float]:
        tokens = self._tokens(text)
        if not tokens:
            return {}
        vector: dict[int, float] = {}
        for token in tokens:
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            raw = int.from_bytes(digest, "big")
            index = raw % self.dimensions
            sign = 1.0 if raw & (1 << 63) else -1.0
            vector[index] = vector.get(index, 0.0) + sign
        norm = math.sqrt(sum(value * value for value in vector.values()))
        if norm == 0:
            return {}
        return {index: value / norm for index, value in vector.items()}

    @staticmethod
    def _tokens(text: str) -> list[str]:
        lowered = str(text or "").lower()
        latin = re.findall(r"[a-z0-9][a-z0-9_.:/{}-]{1,63}", lowered)
        cjk = re.findall(r"[\u4e00-\u9fff]", lowered)
        tokens = latin + cjk
        tokens.extend(f"{latin[idx]}::{latin[idx + 1]}" for idx in range(len(latin) - 1))
        tokens.extend("".join(cjk[idx:idx + 2]) for idx in range(len(cjk) - 1))
        return tokens[:4096]


class MemoryMatcher:
    """Hybrid governed-memory association shared across all model providers."""

    def __init__(self, config: MemoryMatchingConfig | None = None):
        self.config = config or MemoryMatchingConfig()
        total = self.config.structured_weight + self.config.semantic_weight + self.config.retrieval_weight
        if total <= 0:
            raise ValueError("memory matching weights must have a positive sum")
        if min(self.config.structured_weight, self.config.semantic_weight, self.config.retrieval_weight) < 0:
            raise ValueError("memory matching weights cannot be negative")
        if not 0 <= self.config.review_threshold <= self.config.apply_threshold <= 1:
            raise ValueError("memory matching thresholds must satisfy 0 <= review <= apply <= 1")
        self._weight_total = total
        self.vectorizer = HashingTextVectorizer(self.config.vector_dimensions)

    def match(self, event: NormalizedEvent, memories: list[dict[str, Any]]) -> MemoryMatchEvaluation:
        evaluation = MemoryMatchEvaluation(
            event_id=event.event_id,
            alert_id=event.raw_ref,
            product=event.product.lower(),
            matcher_version=MATCHER_VERSION,
            review_threshold=self.config.review_threshold,
            apply_threshold=self.config.apply_threshold,
            config_snapshot={
                "structured_weight": self.config.structured_weight,
                "semantic_weight": self.config.semantic_weight,
                "retrieval_weight": self.config.retrieval_weight,
                "vector_dimensions": self.config.vector_dimensions,
                "semantic_method": SEMANTIC_METHOD,
                "min_high_fields": self.config.min_high_fields,
                "apply_enabled": self.config.apply_enabled,
                "allow_malicious_downgrade": self.config.allow_malicious_downgrade,
                "inject_matches_into_model": self.config.inject_matches_into_model,
            },
        )
        event_payload = {
            "product": event.product,
            "event_type": event.event_type,
            "severity": event.severity,
            "entities": event.entities,
            "evidence": event.evidence,
        }
        event_text = json.dumps(event_payload, ensure_ascii=False, sort_keys=True).lower()
        event_features = self._fingerprint(event_payload)
        evaluation.attack_signal_reasons = self._attack_signal_reasons(event)
        evaluation.attack_signal_veto = bool(evaluation.attack_signal_reasons)
        candidates: list[MemoryMatchCandidate] = []
        for memory in memories:
            candidate = self._score_candidate(event, event_text, event_features, memory)
            if candidate is not None:
                candidates.append(candidate)
        candidates.sort(
            key=lambda item: (
                _MATCH_LEVEL_PRIORITY.get(item.match_level, 9),
                -item.overall_score,
                item.memory_id,
            )
        )
        for rank, candidate in enumerate(candidates, start=1):
            candidate.rank = rank
            if candidate.title_eligible and candidate.policy_effect != "review_only":
                candidate.decision = "apply_candidate" if self.config.apply_enabled else "apply_disabled_review"
            elif candidate.overall_score >= self.config.review_threshold:
                candidate.decision = "review"
            else:
                candidate.decision = "ignored"
        evaluation.candidates = candidates
        if candidates and candidates[0].overall_score >= self.config.review_threshold:
            evaluation.best_memory_id = candidates[0].memory_id
        return evaluation

    def candidate_lookup_keys(self, event: NormalizedEvent) -> list[str]:
        """Return bounded exact keys used to prioritize older governed memories."""
        payload = {
            "product": event.product,
            "event_type": event.event_type,
            "entities": event.entities,
            "evidence": event.evidence,
        }
        features = self._fingerprint(payload)
        keys: set[str] = set()
        for field_name in (
            "rule_id", "event_type", "app", "host", "uri", "method",
            "process", "sink", "user_agent",
        ):
            keys.update(features.get(field_name, set()))
        return sorted(key for key in keys if key)[:32]

    def reconcile(self, result: AgentResult, evaluation: MemoryMatchEvaluation) -> AgentResult:
        best = evaluation.best
        association = evaluation.context_payload(self.config.top_k)
        association["evaluated_candidates"] = len(evaluation.candidates)
        association["final_effect"] = evaluation.final_effect
        result.explanation["memory_association"] = association
        if best is None:
            return result

        original = result.classification
        original_confidence = result.confidence
        original_severity = result.severity
        score = best.overall_score
        memory_confidence = round(min(0.9, 0.55 + 0.4 * score), 2)
        if not best.title_eligible:
            effect = "related_only"
        elif evaluation.attack_signal_veto:
            effect = "attack_signal_veto"
        elif original == "malicious" and not self.config.allow_malicious_downgrade:
            effect = "malicious_requires_review"
        elif not self.config.apply_enabled:
            effect = "apply_disabled_review"
        elif (
            best.policy_effect != "review_only"
            and original in {"malicious", "suspicious", "benign"}
        ):
            effect = "classification_reinforced" if original == "benign" else "downgraded_to_benign"
            result.classification = "benign"
            result.confidence = (
                round(max(result.confidence, memory_confidence), 2)
                if original == "benign"
                else memory_confidence
            )
            result.severity = "low" if result.confidence >= 0.7 else "medium"
        else:
            effect = "review_only"
        evaluation.final_effect = effect
        best.decision = effect
        association["final_effect"] = effect
        association["original_classification"] = original
        association["original_confidence"] = original_confidence
        association["original_severity"] = original_severity
        association["memory_confidence"] = memory_confidence
        association["final_classification"] = result.classification
        association["final_confidence"] = result.confidence
        association["final_severity"] = result.severity

        matched = ", ".join(best.matched_features[:6]) or "词法哈希"
        comparison = best.comparison
        level_label = _MATCH_LEVEL_LABELS.get(best.match_level, best.match_level)
        matched_dimensions = self._dimension_labels(comparison.get("matched_fields")) or "无稳定维度"
        conflicting_dimensions = self._dimension_labels(comparison.get("conflicting_fields")) or "无"
        missing_dimensions = self._dimension_labels(comparison.get("missing_fields")) or "无"
        association_verb = "命中" if best.title_eligible else "关联候选"
        evidence = (
            f"{association_verb}长期记忆 {best.memory_id}；匹配程度：{level_label}；综合分 {score:.2f}；"
            f"结构化 {best.structured_score:.2f}；词法哈希 {best.semantic_score:.2f}；"
            f"检索键 {best.retrieval_score:.2f}；一致维度：{matched_dimensions}；"
            f"冲突维度：{conflicting_dimensions}；缺失维度：{missing_dimensions}；匹配特征：{matched}。"
        )
        dimensions = list(result.explanation.get("dimensions") or [])
        dimensions.append({"title": "历史误报", "status": "benign" if result.classification == "benign" else "review", "evidence": evidence})
        result.explanation["dimensions"] = dimensions
        verdict = str(result.explanation.get("verdict") or "")
        if effect == "related_only":
            result.explanation["verdict"] = f"{verdict}；长期记忆仅部分相似，不构成命中且不作为误报依据"
        elif effect == "downgraded_to_benign":
            result.explanation["verdict"] = "【误报】- 与人工批准的长期记忆高度相似，保留偏离基线复核"
        elif effect == "classification_reinforced":
            result.explanation["verdict"] = f"{verdict}；人工批准的长期记忆进一步支持当前误报结论"
        elif effect == "attack_signal_veto":
            result.explanation["verdict"] = f"{verdict}；相似误报记忆不覆盖当前攻击证据"
        elif effect == "malicious_requires_review":
            result.explanation["verdict"] = f"{verdict}；恶意结论不得由历史误报记忆自动降级，需人工复核"
        elif effect == "apply_disabled_review":
            result.explanation["verdict"] = f"{verdict}；长期记忆仅处于评估模式，未改写当前结论"
        else:
            result.explanation["verdict"] = f"{verdict}；长期记忆达到{level_label}，建议人工复核"
        if best.title_eligible and not result.summary.startswith("【长期记忆命中】"):
            result.summary = f"【长期记忆命中】{result.summary}"
        result.dashboard_cards.append(
            {"title": "记忆关联", "body": f"{best.memory_id} / {level_label} / {score:.2f} / {effect}"}
        )
        if not any("长期记忆" in action.action for action in result.recommended_actions):
            result.recommended_actions.append(
                RecommendedAction(
                    action="复核长期记忆关联边界",
                    mode="automated_read_only",
                    rationale="核对规则、资产、路径、客户端、频率和影响面是否仍符合人工批准范围",
                )
            )
        return result

    def _score_candidate(
        self,
        event: NormalizedEvent,
        event_text: str,
        event_features: dict[str, set[str]],
        memory: dict[str, Any],
    ) -> MemoryMatchCandidate | None:
        if not self._eligible(event, memory, event_features):
            return None
        memory_content = self._content(memory)
        memory_text = json.dumps(memory_content, ensure_ascii=False, sort_keys=True).lower()
        memory_features = self._fingerprint(memory_content)
        raw_retrieval_key = str(memory.get("retrieval_key") or "")
        retrieval_key = self._normalize(raw_retrieval_key, "rule_id")
        # Legacy governed memories may keep their exact rule/event identity only
        # in retrieval_key. Treat it as structured identity solely when it exactly
        # matches the corresponding current-event field.
        if not memory_features["rule_id"] and retrieval_key in event_features.get("rule_id", set()):
            memory_features["rule_id"].add(retrieval_key)
        elif not memory_features["event_type"] and retrieval_key in event_features.get("event_type", set()):
            memory_features["event_type"].add(retrieval_key)
        match_policy = memory_content.get("match_policy", {}) if isinstance(memory_content, dict) else {}
        if not isinstance(match_policy, dict):
            match_policy = {}
        if not self._match_policy_allows(event, event_features, memory_features, match_policy):
            return None
        retrieval_match_fields = [
            field_name
            for field_name, values in event_features.items()
            if field_name != "tokens"
            and values
            and self._normalize(raw_retrieval_key, field_name) in values
        ]
        retrieval_score = 1.0 if retrieval_match_fields else 0.0

        identity_matches = set()
        for field_name in ("rule_id", "event_type"):
            identity_matches.update(event_features.get(field_name, set()) & memory_features.get(field_name, set()))
        stable_matches = set()
        for field_name in ("app", "host", "uri", "method", "process", "sink", "user_agent", "tokens"):
            stable_matches.update(event_features.get(field_name, set()) & memory_features.get(field_name, set()))
        if not identity_matches and not retrieval_score and len(stable_matches) < 2:
            return None

        weighted = 0.0
        available = 0.0
        breakdown: dict[str, float] = {}
        matched_features: list[str] = []
        for field_name, weight in _FEATURE_WEIGHTS.items():
            memory_values = memory_features.get(field_name, set())
            if not memory_values:
                continue
            available += weight
            event_values = event_features.get(field_name, set())
            intersection = memory_values & event_values
            # Candidate containment is intentional: a new alert often has extra
            # correlated evidence (additional rule IDs or paths) that must not
            # dilute an exact match on every value encoded by the governed memory.
            field_score = len(intersection) / len(memory_values) if memory_values else 0.0
            breakdown[field_name] = round(field_score, 4)
            weighted += weight * field_score
            matched_features.extend(f"{field_name}:{value}" for value in sorted(intersection)[:3])
        structured_score = weighted / available if available else 0.0
        semantic_score = self.vectorizer.cosine(event_text, memory_text)
        overall = (
            self.config.structured_weight * structured_score
            + self.config.semantic_weight * semantic_score
            + self.config.retrieval_weight * retrieval_score
        ) / self._weight_total

        # Exact mismatches in the strongest identity fields must materially reduce
        # the score even when a generic URI or application token overlaps.
        if event_features.get("rule_id") and memory_features.get("rule_id") and not (
            event_features["rule_id"] & memory_features["rule_id"]
        ):
            overall -= 0.18
        if event_features.get("event_type") and memory_features.get("event_type") and not (
            event_features["event_type"] & memory_features["event_type"]
        ):
            overall -= 0.12
        overall = round(max(0.0, min(1.0, overall)), 4)
        try:
            policy_threshold = float(match_policy.get("high_similarity_threshold", self.config.apply_threshold))
        except (TypeError, ValueError):
            policy_threshold = self.config.apply_threshold
        apply_threshold = round(max(self.config.apply_threshold, min(1.0, policy_threshold)), 4)
        policy_effect = str(match_policy.get("effect_mode") or "downgrade_to_benign").strip().lower()
        if policy_effect not in {"downgrade_to_benign", "review_only"}:
            policy_effect = "review_only"
        match_level, title_eligible, comparison = self._match_level(
            event_features,
            memory_features,
            breakdown,
            structured_score,
            overall,
            apply_threshold,
        )
        comparison["retrieval_match_fields"] = retrieval_match_fields
        return MemoryMatchCandidate(
            memory_id=str(memory.get("memory_id") or ""),
            memory=memory,
            structured_score=round(structured_score, 4),
            semantic_score=round(semantic_score, 4),
            retrieval_score=round(retrieval_score, 4),
            overall_score=overall,
            matched_features=sorted(set(matched_features))[:16],
            score_breakdown=breakdown,
            match_level=match_level,
            title_eligible=title_eligible,
            comparison=comparison,
            apply_threshold=apply_threshold,
            policy_effect=policy_effect,
        )

    def _match_level(
        self,
        event_features: dict[str, set[str]],
        memory_features: dict[str, set[str]],
        breakdown: dict[str, float],
        structured_score: float,
        overall_score: float,
        apply_threshold: float,
    ) -> tuple[str, bool, dict[str, Any]]:
        matched_fields: list[str] = []
        conflicting_fields: list[str] = []
        missing_fields: list[str] = []
        considered_fields: list[str] = []
        for field_name in _FEATURE_WEIGHTS:
            if field_name == "tokens" or not memory_features.get(field_name):
                continue
            considered_fields.append(field_name)
            event_values = event_features.get(field_name, set())
            if not event_values:
                missing_fields.append(field_name)
            elif event_values & memory_features[field_name]:
                matched_fields.append(field_name)
            else:
                conflicting_fields.append(field_name)

        identity_defined = [field for field in _IDENTITY_FIELDS if memory_features.get(field)]
        identity_matched = [field for field in identity_defined if field in matched_fields]
        identity_gate = bool(identity_matched) and all(field in matched_fields for field in identity_defined)
        behavior_defined = [
            field for field in _BEHAVIOR_BOUNDARY_FIELDS if memory_features.get(field)
        ]
        behavior_matched = [field for field in behavior_defined if field in matched_fields]
        boundary_conflicts = [
            field
            for field in (*_IDENTITY_FIELDS, *_BEHAVIOR_BOUNDARY_FIELDS)
            if field in conflicting_fields
        ]
        context_matched = [field for field in _CONTEXT_FIELDS if field in matched_fields]
        stable_behavior_gate = bool(behavior_matched) or len(context_matched) >= 2
        all_defined_match = bool(considered_fields) and all(
            field in matched_fields and breakdown.get(field, 0.0) == 1.0
            for field in considered_fields
        )
        coverage_gate = len(considered_fields) >= self.config.min_high_fields
        exact = (
            identity_gate
            and stable_behavior_gate
            and coverage_gate
            and all_defined_match
            and overall_score >= apply_threshold
        )
        high = (
            identity_gate
            and stable_behavior_gate
            and coverage_gate
            and not boundary_conflicts
            and structured_score >= 0.72
            and overall_score >= apply_threshold
        )
        if exact:
            level = "exact"
        elif high:
            level = "high"
        elif overall_score >= self.config.review_threshold:
            level = "related"
        else:
            level = "weak"

        gate_reasons: list[str] = []
        if not identity_gate:
            gate_reasons.append("identity_not_fully_matched")
        if not stable_behavior_gate:
            gate_reasons.append("stable_behavior_not_matched")
        if not coverage_gate:
            gate_reasons.append("insufficient_feature_coverage")
        if boundary_conflicts:
            gate_reasons.append("boundary_conflict")
        if structured_score < 0.72:
            gate_reasons.append("structured_similarity_below_0.72")
        if overall_score < apply_threshold:
            gate_reasons.append("overall_similarity_below_apply_threshold")
        return level, level in {"exact", "high"}, {
            "matched_fields": matched_fields,
            "conflicting_fields": conflicting_fields,
            "missing_fields": missing_fields,
            "identity_fields": identity_defined,
            "behavior_fields": behavior_defined,
            "considered_fields": considered_fields,
            "considered_field_count": len(considered_fields),
            "min_high_fields": self.config.min_high_fields,
            "gate_reasons": gate_reasons,
        }

    @staticmethod
    def _dimension_labels(fields: Any) -> str:
        if not isinstance(fields, list):
            return ""
        return "、".join(_FIELD_LABELS.get(str(field), str(field)) for field in fields)

    def _eligible(
        self,
        event: NormalizedEvent,
        memory: dict[str, Any],
        event_features: dict[str, set[str]],
    ) -> bool:
        if memory.get("status") != "active":
            return False
        if str(memory.get("trust_level") or "low").lower() not in {"medium", "high"}:
            return False
        if not memory.get("approved_by") or not memory.get("sensitivity_ok", 1):
            return False
        expiry = memory.get("expires_at_ms")
        if expiry is not None and int(expiry) <= now_ms():
            return False
        expected_namespace = f"product/{event.product.lower()}"
        if str(memory.get("namespace") or "").lower() != expected_namespace:
            return False
        content = self._content(memory)
        if not self._scope_allows(event, event_features, str(memory.get("scope") or "")):
            return False
        content_text = json.dumps(content, ensure_ascii=False, sort_keys=True).lower()
        if isinstance(content, dict):
            features = content.get("features") if isinstance(content.get("features"), dict) else {}
            product = str(content.get("product") or features.get("product") or "").lower()
            if product and product != event.product.lower():
                return False
            governed_false_positive = bool(
                str(content.get("classification") or "").lower() == "benign"
                and (
                    content.get("human_confirmed")
                    or content.get("false_positive_candidate")
                    or str(content.get("confirmation_type") or "").lower() == "business_false_positive"
                )
            )
        else:
            governed_false_positive = any(marker in content_text for marker in _FALSE_POSITIVE_MARKERS)
        return governed_false_positive

    def _scope_allows(
        self,
        event: NormalizedEvent,
        event_features: dict[str, set[str]],
        scope: str,
    ) -> bool:
        normalized_scope = scope.strip().lower()
        if not normalized_scope:
            return False
        try:
            structured = json.loads(normalized_scope)
        except json.JSONDecodeError:
            structured = None
        if isinstance(structured, dict):
            purpose = str(structured.get("purpose") or "").lower()
            if purpose not in _FALSE_POSITIVE_SCOPES:
                return False
            products = self._as_values(structured.get("products") or structured.get("product"))
            if products and event.product.lower() not in products:
                return False
            constraints = {
                "event_type": structured.get("event_types") or structured.get("event_type"),
                "rule_id": structured.get("rule_ids") or structured.get("rule_id"),
                "app": structured.get("apps") or structured.get("app"),
                "host": structured.get("assets") or structured.get("host"),
            }
            for field_name, expected in constraints.items():
                values = {self._normalize(value, field_name) for value in self._as_values(expected)}
                values.discard("")
                if values and not (values & event_features.get(field_name, set())):
                    return False
            return True

        parts = [part.strip() for part in normalized_scope.split(":")]
        if len(parts) < 2 or parts[0] != event.product.lower() or parts[1] not in _FALSE_POSITIVE_SCOPES:
            return False
        if len(parts) >= 3 and parts[2] not in {"", "*", "all"}:
            if self._normalize(parts[2], "event_type") not in event_features.get("event_type", set()):
                return False
        return True

    def _match_policy_allows(
        self,
        event: NormalizedEvent,
        event_features: dict[str, set[str]],
        memory_features: dict[str, set[str]],
        policy: dict[str, Any],
    ) -> bool:
        if not policy:
            return True

        def matches(field_name: str) -> bool:
            canonical = _FIELD_ALIASES.get(field_name.lower(), field_name.lower())
            if canonical == "product":
                return True
            return bool(event_features.get(canonical, set()) & memory_features.get(canonical, set()))

        must_all = [str(item) for item in self._as_values(policy.get("must_match_all"))]
        if must_all and not all(matches(field_name) for field_name in must_all):
            return False
        # Product is already a hard namespace/scope constraint. It must not make
        # ``must_match_any`` vacuously true when event/rule identity differs.
        must_any = [
            str(item) for item in self._as_values(policy.get("must_match_any"))
            if str(item).lower() != "product"
        ]
        if must_any and not any(matches(field_name) for field_name in must_any):
            return False
        must_not = [str(item) for item in self._as_values(policy.get("must_not_match"))]
        if must_not and any(matches(field_name) for field_name in must_not):
            return False

        required_values = policy.get("required_values")
        if isinstance(required_values, dict):
            for field_name, expected in required_values.items():
                canonical = _FIELD_ALIASES.get(str(field_name).lower(), str(field_name).lower())
                if canonical == "product":
                    if event.product.lower() not in self._as_values(expected):
                        return False
                    continue
                normalized = {
                    self._normalize(value, canonical) for value in self._as_values(expected)
                }
                normalized.discard("")
                if normalized and not (normalized & event_features.get(canonical, set())):
                    return False
        return True

    @staticmethod
    def _as_values(value: Any) -> set[str]:
        if value in (None, ""):
            return set()
        if isinstance(value, (list, tuple, set)):
            return {str(item).strip().lower() for item in value if str(item).strip()}
        return {str(value).strip().lower()}

    def _attack_signal_reasons(self, event: NormalizedEvent) -> list[str]:
        """Identify strong attack facts from the current event, not model output."""
        by_type: dict[str, list[Any]] = {}
        for item in event.evidence:
            if not isinstance(item, dict):
                continue
            evidence_type = str(item.get("type") or "").strip().lower()
            if evidence_type in {"expected_verdict", "analysis_dimension"}:
                continue
            by_type.setdefault(evidence_type, []).append(item.get("value"))

        reasons: list[str] = []
        runtime_chain = {"sink", "stacktrace", "stack_trace", "hook_data", "taint_source"} & set(by_type)
        if "sink" in runtime_chain and len(runtime_chain) >= 2:
            reasons.append("runtime_sink_chain")

        for evidence_type in _CURRENT_ATTACK_EVIDENCE_TYPES:
            values = by_type.get(evidence_type, [])
            if any(_CURRENT_ATTACK_PATTERN.search(json.dumps(value, ensure_ascii=False)) for value in values):
                reasons.append(f"explicit_{evidence_type}")

        action = str(event.entities.get("action") or "").lower()
        if runtime_chain and any(term in action for term in ("block", "kill", "terminate", "阻断")):
            reasons.append("runtime_protection_blocked_chain")
        return sorted(set(reasons))

    def _fingerprint(self, payload: Any) -> dict[str, set[str]]:
        fields: dict[str, set[str]] = {name: set() for name in _FEATURE_WEIGHTS}

        def visit(value: Any, key: str = "") -> None:
            canonical = _FIELD_ALIASES.get(str(key).lower())
            if canonical and value is not None and not isinstance(value, (dict, list)):
                normalized = self._normalize(value, canonical)
                if normalized:
                    fields[canonical].add(normalized)
            if isinstance(value, dict):
                evidence_type = str(value.get("type") or "").lower()
                if evidence_type and "value" in value:
                    visit(value.get("value"), evidence_type)
                for child_key, child in value.items():
                    visit(child, str(child_key))
            elif isinstance(value, list):
                for child in value[:200]:
                    visit(child, key)

        visit(payload)
        # Regex fallback is only for legacy unstructured memories. Applying it to
        # structured JSON would misclassify alert IDs such as HIPS-2026-* as rule
        # IDs even though their key is explicitly ``alert_id``.
        if isinstance(payload, str):
            text = payload.lower()
            fields["rule_id"].update(re.findall(r"\b(?:waf|hips|rasp|ndr|siem)-[a-z0-9-]+", text))
            fields["uri"].update(self._normalize(item, "uri") for item in re.findall(r"/[a-z0-9_./{}-]+", text))
            fields["process"].update(re.findall(r"\b[a-z0-9_.-]+\.exe\b", text))
            fields["tokens"].update(
                re.findall(
                    r"\b[a-z0-9_-]+(?:-api|-web|-gateway|-service|-client|-srv|-prod)(?:/[0-9.]+)?\b",
                    text,
                )
            )
            fields["tokens"].discard("")
        for field_name in ("app", "host", "process", "user_agent"):
            fields["tokens"].update(fields[field_name])
        return fields

    @staticmethod
    def _content(memory: dict[str, Any]) -> Any:
        content = memory.get("content") or ""
        if not isinstance(content, str):
            return content
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return content

    @staticmethod
    def _normalize(value: Any, field_name: str) -> str:
        normalized = str(value or "").strip().lower().rstrip(".,;:")
        if not normalized:
            return ""
        if field_name == "uri":
            try:
                path = urlsplit(normalized).path if "://" in normalized else normalized.split("?", 1)[0]
            except ValueError:
                path = normalized.split("?", 1)[0]
            segments = []
            for segment in path.split("/"):
                if re.fullmatch(r"\d+|[0-9a-f]{8}-[0-9a-f-]{27,}", segment):
                    segments.append("{id}")
                else:
                    segments.append(segment)
            normalized = "/".join(segments)
        elif field_name == "user_agent":
            normalized = re.sub(r"\d+(?:\.\d+)+", "{version}", normalized)
        return normalized[:256]
