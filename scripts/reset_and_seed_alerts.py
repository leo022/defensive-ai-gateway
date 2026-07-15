from __future__ import annotations

# ruff: noqa: E402 -- source checkout scripts add the project root before imports.

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defensive_ai_gateway.config import GatewayConfig, load_config
from defensive_ai_gateway.database import Repository
from defensive_ai_gateway.llm import LocalHeuristicLLM
from defensive_ai_gateway.memory import LAYER_PRODUCT_LONG_TERM, STATUS_PENDING, MemoryManager
from defensive_ai_gateway.models import RawAlert, now_ms
from defensive_ai_gateway.normalizer import EventNormalizer
from defensive_ai_gateway.orchestrator import Orchestrator
from defensive_ai_gateway.policy import PolicyEngine
from defensive_ai_gateway.sample_alerts import PRODUCTS, generate_alert


def _raw_alert(payload: dict) -> RawAlert:
    return RawAlert(
        source=str(payload.get("source", "seed")),
        product=str(payload.get("product", "siem")),
        event_type=str(payload.get("event_type", "unknown")),
        severity=str(payload.get("severity", "medium")),
        timestamp=str(payload.get("timestamp", "")),
        payload=dict(payload.get("payload", payload)),
        alert_id=str(payload.get("alert_id", payload.get("id", ""))),
        trusted_sample=True,
    )


def _remove_db(path: Path) -> None:
    for suffix in ["", "-wal", "-shm"]:
        target = Path(str(path) + suffix)
        if target.exists():
            target.unlink()


def _promote_false_positive_candidates(repo: Repository, memory: MemoryManager) -> list[str]:
    promoted: list[str] = []
    future = now_ms() + 90 * 24 * 3600 * 1000
    rows = repo.query_memory(layer=LAYER_PRODUCT_LONG_TERM, status=STATUS_PENDING, limit=500, include_expired=True)
    for row in rows:
        content = row.get("content", "")
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = {}
        if not (data.get("false_positive_candidate") or data.get("classification") == "benign"):
            continue
        retrieval_key = _retrieval_key_from_candidate(row, data)
        outcome = memory.promote(
            row["memory_id"],
            approved_by="seed-analyst",
            scope=f"{row['namespace']}:false_positive_similarity",
            expires_at_ms=future,
            retrieval_key=retrieval_key,
        )
        if outcome.ok:
            promoted.append(row["memory_id"])
    return promoted


def _similar_review_alert(product: str, seed: int) -> dict:
    payload = generate_alert(product=product, scenario="false_positive", seed=seed)
    payload["alert_id"] = f"{payload['alert_id']}-review"
    payload["event_type"] = f"{payload['event_type']}_similar_review"
    payload["severity"] = "medium"
    body = payload["payload"]
    body["memory_hint"] = "new_alert_highly_similar_to_promoted_false_positive"
    body["review_reason"] = "current alert is similar to an approved false-positive pattern but still requires boundary checks"
    original = body.get("evidence_assessment", {})
    dimensions = []
    for item in original.get("analysis_dimensions", []) or []:
        if isinstance(item, dict):
            dimensions.append({**item, "status": "review"})
    dimensions.append(
        {
            "title": "历史相似性",
            "status": "review",
            "evidence": "该新告警保留了已晋升误报记忆的核心特征，等待 Memory Manager 相似度判断。",
        }
    )
    body["evidence_assessment"] = {
        "expected_verdict": "【需人工复核】- 与历史误报高度相似，需确认当前是否仍符合白名单边界",
        "analysis_dimensions": dimensions,
        "success_assessment": "暂未发现攻击成功证据；需要复核当前频率、来源、资产和业务窗口是否偏离历史误报。",
        "business_impact": "若确认仍符合历史误报模式，可降低告警噪声；若出现偏离，应升级人工复核。",
        "missing_evidence": ["当前来源与历史来源对比", "频率是否偏离基线", "业务 Owner 或变更窗口确认"],
    }
    return payload


def _retrieval_key_from_candidate(row: dict, data: dict) -> str:
    features = data.get("similarity_features") or []
    for feature in features:
        text = str(feature)
        if text.startswith(("waf-", "hips-", "rasp-", "ndr-", "siem-")):
            return text.upper()
    return str(row.get("retrieval_key") or row.get("source_case_id") or row["memory_id"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset local data and seed realistic security alerts")
    parser.add_argument("--config", default="config/dev.yaml")
    parser.add_argument("--per-product", type=int, default=2, help="Alerts per product per scenario")
    parser.add_argument("--similar-followups", type=int, default=1, help="Suspicious follow-up alerts per product after FP memories are promoted")
    parser.add_argument("--seed", type=int, default=20260624)
    parser.add_argument("--keep-db", action="store_true", help="Do not delete the existing database before seeding")
    args = parser.parse_args()

    config = load_config(args.config) if args.config else GatewayConfig()
    db_path = Path(config.database.path)
    if not args.keep_db:
        _remove_db(db_path)

    repo = Repository(str(db_path))
    policy = PolicyEngine(config.policy)
    memory = MemoryManager(repo, policy)
    orchestrator = Orchestrator(repo, EventNormalizer(policy), memory, LocalHeuristicLLM(), policy)

    results = []
    scenarios = ("attack", "suspicious", "false_positive")
    for p_idx, product in enumerate(PRODUCTS):
        for s_idx, scenario in enumerate(scenarios):
            for n in range(args.per_product):
                seed = args.seed + p_idx * 1000 + s_idx * 100 + n
                payload = generate_alert(product=product, scenario=scenario, seed=seed)
                result = orchestrator.handle_alert(_raw_alert(payload))
                results.append(
                    {
                        "product": product,
                        "scenario": scenario,
                        "alert_id": payload["alert_id"],
                        "case_id": result.case_id,
                        "classification": result.classification,
                        "severity": result.severity,
                        "confidence": result.confidence,
                        "verdict": result.explanation.get("verdict"),
                    }
                )

    promoted = _promote_false_positive_candidates(repo, memory)
    followups = []
    for p_idx, product in enumerate(PRODUCTS):
        for n in range(args.similar_followups):
            seed = args.seed + 90000 + p_idx * 100 + n
            payload = _similar_review_alert(product, seed)
            result = orchestrator.handle_alert(_raw_alert(payload))
            item = {
                "product": product,
                "scenario": "similar_suspicious_followup",
                "alert_id": payload["alert_id"],
                "case_id": result.case_id,
                "classification": result.classification,
                "severity": result.severity,
                "confidence": result.confidence,
                "verdict": result.explanation.get("verdict"),
            }
            followups.append(item)
            results.append(item)
    print(
        json.dumps(
            {
                "database": str(db_path),
                "reset": not args.keep_db,
                "alerts_seeded": len(results),
                "similar_followups_seeded": len(followups),
                "false_positive_memories_promoted": len(promoted),
                "promoted_memory_ids": promoted,
                "stats": repo.stats(),
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
